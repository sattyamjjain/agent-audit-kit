"""Go and crates.io as advisory ecosystems, and AAK-KNOWN-VULN-001 on go.mod and Cargo.lock.

Two records are the cases. mcp-go's CVE-2026-123272 (5 Nov 2026) names
`pkg:golang/github.com/mark3labs/mcp-go`, v0.48.0 up to v1.2.1: a malicious MCP server
gets the user's token minted for another resource. SurrealDB's CVE-2026-121419 (3 Nov
2026) names `pkg:cargo/surrealdb`, 3.1.0 up to 3.3.0: a low-privilege token takes over
another user's MCP session. Both are bundled, so these tests read no network, and the
saved records are under tests/fixtures/nvd_cna, unedited.
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
from agent_audit_kit.scanners import agent_server_noauth, known_vulns, malicious_releases, mcp_codeexec_sandbox
from agent_audit_kit.scanners.supply_chain import _lockfile_canon

FIXTURES = Path(__file__).parent / "fixtures"
GO_FIXTURES = FIXTURES / "known_vulns" / "go"
CARGO_FIXTURES = FIXTURES / "known_vulns" / "cargo"
CVE = "CVE-2026-121419"
GO_CVE = "CVE-2026-123272"
MCP_GO = "github.com/mark3labs/mcp-go"
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
    result = run_scan(project_root=CARGO_FIXTURES / "surrealdb-3.2.1", rules=[RULE])
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


@pytest.mark.parametrize("purl", ["pkg:maven/org.apache/log4j", "pkg:cargo/two/segments", "pkg:cargo/", "pkg:golang/"])
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


def _opener(calls: list[str], crates: bytes | None, go: bytes | None):
    def opener(request: urllib.request.Request, timeout: float | None = None) -> _Response:
        calls.append(request.full_url)
        for suffix, body in (("/crates.io/all.zip", crates), ("/Go/all.zip", go)):
            if request.full_url.endswith(suffix):
                if body is None:
                    raise urllib.error.URLError("offline")
                return _Response(body)
        return _Response(_export({}))

    return opener


@pytest.fixture
def update(monkeypatch: pytest.MonkeyPatch):
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def run(crates: bytes | None, go: bytes | None = _export({})) -> Any:
        calls: list[str] = []
        monkeypatch.setattr(malicious_feed.urllib.request, "urlopen", _opener(calls, crates, go))
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
    assert "1 packages (PyPI 0, npm 0, crates.io 1, Go 0)" in result.output
    assert result.calls.count(malicious_feed.OSV_EXPORT.format(ecosystem="crates.io")) == 1
    data = json.loads(advisory_feed.cache_path().read_text())
    assert [e["id"] for e in data["entries"]] == ["RUSTSEC-2026-0002"]
    assert malicious_feed.OSV_EXPORT.format(ecosystem="crates.io") in data["source"]
    _lock(tmp_path, "1.0.0", name="crate_a")
    (finding,) = _findings(tmp_path)
    assert "RUSTSEC-2026-0002" in finding.evidence and "fixed in 1.2.0" in finding.evidence


def test_the_malicious_feed_takes_the_mal_records_of_the_same_download(update: Any, tmp_path: Path) -> None:
    result = update(_export({"MAL-2026-1": _crate_record("MAL-2026-1", name="crate-c")}))
    assert result.exit_code == 0, result.output
    assert result.calls.count(malicious_feed.OSV_EXPORT.format(ecosystem="crates.io")) == 1
    data = json.loads(malicious_feed.cache_path().read_text())
    assert [e["id"] for e in data["entries"] if e["ecosystem"] == "crates.io"] == ["MAL-2026-1", "MAL-2026-18776"]
    assert malicious_feed.OSV_EXPORT.format(ecosystem="crates.io") in data["source"]
    assert not json.loads(advisory_feed.cache_path().read_text())["entries"]  # the advisory feed reads no MAL-
    _lock(tmp_path, "1.0.0", name="crate_c")
    (finding,) = malicious_releases.scan(tmp_path)[0]
    assert finding.rule_id == "AAK-MALICIOUS-RELEASE-001" and "MAL-2026-1," in finding.evidence


def test_a_failed_crates_download_keeps_both_cached_feeds(update: Any) -> None:
    assert update(_export({"RUSTSEC-2026-0002": _crate_record("RUSTSEC-2026-0002")})).exit_code == 0
    before = advisory_feed.cache_path().read_bytes(), malicious_feed.cache_path().read_bytes()
    result = update(None)
    assert result.exit_code != 0
    assert "Malicious-release feed update failed" in result.output and "Advisory feed not rebuilt" in result.output
    assert (advisory_feed.cache_path().read_bytes(), malicious_feed.cache_path().read_bytes()) == before


def test_a_corrupt_export_fails_cleanly(update: Any) -> None:
    result = update(b"not a zip")
    assert result.exit_code != 0 and "Malicious-release feed update failed" in result.output
    assert not advisory_feed.cache_path().is_file() and not malicious_feed.cache_path().is_file()


def test_no_export_leaves_a_download_behind(update: Any) -> None:
    update(_export({}))
    assert not list(advisory_feed.cache_path().parent.glob(".osv-export-*"))


def test_a_collector_counts_every_registry_it_read() -> None:
    written = advisory_feed.Collector().write(now=datetime(2026, 11, 7, tzinfo=timezone.utc))
    assert written.counts == {"PyPI": 0, "npm": 0, "crates.io": 0, "Go": 0}


# -- who else reads the lockfile table -------------------------------------------------------


def test_a_crate_named_like_a_python_distribution_is_not_that_distribution(tmp_path: Path) -> None:
    lock = _lock(tmp_path, "1.0.0", name="openhands_sdk")
    assert agent_server_noauth._releases(tmp_path, [lock], []) == []


def test_supply_002_still_reads_the_file_on_its_own(tmp_path: Path) -> None:
    from agent_audit_kit.scanners.supply_chain import _scan_rust_deps

    _lock(tmp_path)
    assert [f.rule_id for f in _scan_rust_deps(tmp_path) if f.rule_id == "AAK-SUPPLY-002"] == []


# -- go.mod ----------------------------------------------------------------------------------


def _go_mod(root: Path, body: str, head: str = "module example.com/agent\n\ngo 1.22\n\n") -> Path:
    path = root / "go.mod"
    path.write_text(head + body)
    return root


def test_a_required_release_in_range_gives_one_finding_on_its_line() -> None:
    result = run_scan(project_root=GO_FIXTURES / "mcp-go-v1.1.0", rules=[RULE])
    (finding,) = result.findings
    assert finding.file_path == "go.mod" and finding.line_number == 5 and finding.severity is Severity.HIGH
    assert GO_CVE in finding.evidence and "fixed in v1.2.1" in finding.evidence
    assert f"go.mod requires {MCP_GO} v1.1.0" in finding.evidence
    assert "only part of the build" not in finding.evidence


@pytest.mark.parametrize("project", ["mcp-go-v1.2.1", "mcp-go-v0.47.0", "replace-local", "replace-fixed", "go-sum-only"])
def test_a_project_the_advisory_does_not_reach_gives_none(project: str) -> None:
    assert run_scan(project_root=GO_FIXTURES / project, rules=[RULE]).findings == []


def test_an_indirect_requirement_in_a_block_still_reports() -> None:
    (finding,) = run_scan(project_root=GO_FIXTURES / "indirect", rules=[RULE]).findings
    assert finding.line_number == 7 and GO_CVE in finding.evidence


@pytest.mark.parametrize("version", ["v0.48.0", "v1.2.0", "v1.2.1-rc.1", "v1.2.1-0.20261101000000-abcdef123456"])
def test_the_range_is_read_as_go_versions(tmp_path: Path, version: str) -> None:
    assert len(_findings(_go_mod(tmp_path, f"require {MCP_GO} {version}\n"))) == 1


@pytest.mark.parametrize("version", ["v0.0.0-20261101000000-abcdef123456", "v1.2.1", "v1.5.0", "v2.0.0+incompatible"])
def test_a_go_version_outside_the_range_gives_none(tmp_path: Path, version: str) -> None:
    assert _findings(_go_mod(tmp_path, f"require {MCP_GO} {version}\n")) == []


def test_a_mixed_case_module_is_compared_as_written(tmp_path: Path) -> None:
    assert _findings(_go_mod(tmp_path, "require github.com/Mark3Labs/MCP-Go v1.1.0\n")) == []


def test_a_major_version_path_is_another_module(tmp_path: Path) -> None:
    assert _findings(_go_mod(tmp_path, f"require {MCP_GO}/v2 v2.0.0\n")) == []


def test_a_replace_to_another_affected_release_reports_it_at_the_replace_line(tmp_path: Path) -> None:
    (finding,) = _findings(_go_mod(tmp_path, f"require {MCP_GO} v0.1.0\n\nreplace {MCP_GO} => {MCP_GO} v1.1.0\n"))
    assert finding.line_number == 7 and f"{MCP_GO} v1.1.0" in finding.evidence


def test_a_replace_of_another_module_with_an_affected_one_reports_the_replacement(tmp_path: Path) -> None:
    (finding,) = _findings(_go_mod(tmp_path, f"require example.com/x v1.0.0\nreplace example.com/x => {MCP_GO} v1.1.0\n"))
    assert finding.line_number == 6


def test_a_replace_naming_another_version_leaves_this_one_alone(tmp_path: Path) -> None:
    assert len(_findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nreplace {MCP_GO} v1.0.0 => {MCP_GO} v1.2.1\n"))) == 1
    assert _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nreplace {MCP_GO} v1.1.0 => {MCP_GO} v1.2.1\n")) == []


def test_a_version_replace_beats_a_module_replace(tmp_path: Path) -> None:
    body = f"require {MCP_GO} v1.1.0\nreplace {MCP_GO} => {MCP_GO} v1.1.5\nreplace {MCP_GO} v1.1.0 => {MCP_GO} v1.2.1\n"
    assert _findings(_go_mod(tmp_path, body)) == []


@pytest.mark.parametrize("target", ["./mcp-go", "../mcp-go", "/abs/mcp-go", '"./my dir"', ".\\\\mcp-go", "..\\\\mcp-go", "C:\\\\mcp-go"])
def test_a_replace_to_a_local_path_drops_the_module(tmp_path: Path, target: str) -> None:
    assert _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nreplace {MCP_GO} => {target}\n")) == []


def test_a_replace_in_a_block_applies(tmp_path: Path) -> None:
    assert _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nreplace (\n\t{MCP_GO} => ../x // ours\n)\n")) == []


def test_a_trailing_comment_does_not_undo_a_replace(tmp_path: Path) -> None:
    assert _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nreplace {MCP_GO} => {MCP_GO} v1.2.1 // the fix\n")) == []


def test_a_replace_after_a_closed_block_is_read_as_a_replace(tmp_path: Path) -> None:
    assert _findings(_go_mod(tmp_path, f"require (\n\t{MCP_GO} v1.1.0\n)\n\nreplace {MCP_GO} => ../mcp-go\n")) == []


@pytest.mark.parametrize("line", [
    "replace => ../mcp-go",
    "replace github.com/mark3labs/mcp-go =>",
    "replace github.com/mark3labs/mcp-go v1.1.0 extra => ../mcp-go",
    "replace github.com/mark3labs/mcp-go => example.com/fork v1.0.0 extra",
    "replace github.com/mark3labs/mcp-go ../mcp-go",
])
def test_a_replace_go_would_refuse_changes_nothing(tmp_path: Path, line: str) -> None:
    assert len(_findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\n{line}\n"))) == 1


def test_a_replacement_module_with_no_version_changes_nothing(tmp_path: Path) -> None:
    """Go requires a version for a module on the right, so this is no replacement."""
    assert len(_findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nreplace {MCP_GO} => example.com/fork\n"))) == 1


def test_lines_stay_right_when_a_replace_sits_after_a_later_require(tmp_path: Path) -> None:
    body = (f"require example.com/x v1.0.0\nrequire {MCP_GO} v1.1.0\n\n"
            "replace example.com/x => github.com/diillson/chatcli v1.200.0\n")
    found = {f.line_number: f.evidence.split(" v")[0] for f in _findings(_go_mod(tmp_path, body))}
    assert found == {6: f"go.mod requires {MCP_GO}", 8: "go.mod requires github.com/diillson/chatcli"}


def test_a_replace_nothing_requires_reports_nothing(tmp_path: Path) -> None:
    assert _findings(_go_mod(tmp_path, f"replace example.com/x => {MCP_GO} v1.1.0\n")) == []


def test_exclude_is_ignored(tmp_path: Path) -> None:
    assert len(_findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nexclude {MCP_GO} v1.1.0\n"))) == 1
    assert _findings(_go_mod(tmp_path, f"exclude (\n\t{MCP_GO} v1.1.0\n)\n")) == []


def test_comments_are_no_requirements(tmp_path: Path) -> None:
    body = f"// require {MCP_GO} v1.1.0\nrequire (\n\t// {MCP_GO} v1.1.0\n)\n"
    assert _findings(_go_mod(tmp_path, body)) == []


def test_a_comment_stuck_to_the_version_is_still_a_comment(tmp_path: Path) -> None:
    assert len(_findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0//indirect\n"))) == 1


def test_a_quoted_requirement_and_crlf_are_read(tmp_path: Path) -> None:
    assert len(_findings(_go_mod(tmp_path, f'require "{MCP_GO}" "v1.1.0"\r\n'))) == 1


def test_a_file_only_named_like_go_mod_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "go.mod.bak").write_text(f"require {MCP_GO} v1.1.0\n")
    assert _findings(tmp_path) == []


def test_a_nested_module_is_read(tmp_path: Path) -> None:
    nested = tmp_path / "services" / "api"
    nested.mkdir(parents=True)
    _go_mod(nested, f"require {MCP_GO} v1.1.0\n")
    assert [f.file_path for f in _findings(tmp_path)] == ["services/api/go.mod"]


def test_a_vendored_module_is_not_read(tmp_path: Path) -> None:
    vendored = tmp_path / "vendor" / "example.com" / "x"
    vendored.mkdir(parents=True)
    _go_mod(vendored, f"require {MCP_GO} v1.1.0\n")
    assert _findings(tmp_path) == []


# -- a go.mod that lists only part of the build ---------------------------------------------


@pytest.mark.parametrize("line, words", [
    ("go 1.16", "says go 1.16, older than 1.17"),
    ("go 1.9", "says go 1.9, older than 1.17"),
    ("", "has no go line, which Go reads as 1.16"),
])
def test_an_old_go_mod_says_it_lists_only_part_of_the_build(tmp_path: Path, line: str, words: str) -> None:
    (finding,) = _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\n", head=f"module m\n\n{line}\n\n"))
    assert words in finding.evidence and "only part of the build" in finding.evidence


@pytest.mark.parametrize("line", ["go 1.17", "go 1.22", "go 1.22.1", "go 1.25rc1", "go 2.0", "  go 1.21"])
def test_a_go_mod_from_1_17_claims_nothing_extra(tmp_path: Path, line: str) -> None:
    (finding,) = _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\n", head=f"module m\n\n{line}\n\n"))
    assert "only part of the build" not in finding.evidence


def test_a_commented_go_line_is_no_go_line(tmp_path: Path) -> None:
    (finding,) = _findings(_go_mod(tmp_path, f"require {MCP_GO} v1.1.0\n", head="module m\n\n// go 1.22\n\n"))
    assert "has no go line" in finding.evidence


# -- both exports ----------------------------------------------------------------------------


def _go_record(ident: str, name: str = MCP_GO, **extra: Any) -> dict[str, Any]:
    return {"id": ident, "modified": "2026-11-01T00:00:00Z", **extra, "affected": [{
        "package": {"ecosystem": "Go", "name": name},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.9.0"}]}],
    }]}


def test_aak_update_reads_the_go_export_and_counts_it(update: Any, tmp_path: Path) -> None:
    go = _export({"GHSA-aaaa": _go_record("GHSA-aaaa"), "MAL-2026-1": _go_record("MAL-2026-1", name="example.com/mal")})
    crates = _export({"RUSTSEC-2026-0002": _crate_record("RUSTSEC-2026-0002")})
    result = update(crates, go)
    assert result.exit_code == 0, result.output
    assert "2 packages (PyPI 0, npm 0, crates.io 1, Go 1)" in result.output
    assert result.calls.count(malicious_feed.OSV_EXPORT.format(ecosystem="Go")) == 1
    data = json.loads(advisory_feed.cache_path().read_text())
    assert malicious_feed.OSV_EXPORT.format(ecosystem="Go") in data["source"]
    _go_mod(tmp_path, f"require {MCP_GO} v1.5.0\n")
    ids = {f.evidence.split("which ")[1].split(" ")[0] for f in _findings(tmp_path)}
    assert "GHSA-aaaa" in ids and "fixed in 1.9.0" in " ".join(f.evidence for f in _findings(tmp_path))


def test_a_go_record_and_its_ghsa_twin_are_one_finding(update: Any, tmp_path: Path) -> None:
    go = _export({
        "GO-2026-1": _go_record("GO-2026-1", name="example.com/twin", aliases=["GHSA-bbbb", "CVE-2026-1"]),
        "GHSA-bbbb": _go_record("GHSA-bbbb", name="example.com/twin", aliases=["GO-2026-1", "CVE-2026-1"]),
    })
    assert update(_export({}), go).exit_code == 0
    _go_mod(tmp_path, "require example.com/twin v1.0.0\n")
    assert len(_findings(tmp_path)) == 1


def test_a_failed_go_download_rebuilds_neither_feed(update: Any) -> None:
    first = update(_export({"RUSTSEC-2026-0002": _crate_record("RUSTSEC-2026-0002")}), _export({"GHSA-aaaa": _go_record("GHSA-aaaa")}))
    assert first.exit_code == 0, first.output
    result = update(_export({"RUSTSEC-2026-0003": _crate_record("RUSTSEC-2026-0003", name="crate-b")}), None)
    assert result.exit_code != 0 and "Go/all.zip" in result.calls[-1]
    data = json.loads(advisory_feed.cache_path().read_text())
    assert sorted(e["id"] for e in data["entries"]) == ["GHSA-aaaa", "RUSTSEC-2026-0002"]


def test_both_feeds_read_the_same_four_registries() -> None:
    assert malicious_feed.ECOSYSTEMS == ("PyPI", "npm", "crates.io", "Go")
    assert advisory_feed.ADVISORY_ECOSYSTEMS == malicious_feed.ECOSYSTEMS


# -- who else reads the lockfile table, on a go.mod ------------------------------------------


def test_a_go_mod_is_no_python_distribution(tmp_path: Path) -> None:
    _go_mod(tmp_path, "require openhands-sdk v1.0.0\n")
    assert agent_server_noauth._releases(tmp_path, [tmp_path / "go.mod"], []) == []


def test_a_go_mod_gives_the_malicious_and_sandbox_readers_nothing(tmp_path: Path) -> None:
    _go_mod(tmp_path, f"require {MCP_GO} v1.1.0\nrequire prefab-ui v0.14.0\n")
    assert malicious_releases.scan(tmp_path)[0] == []
    assert mcp_codeexec_sandbox.scan(tmp_path)[0] == []


def test_supply_002_still_does_not_read_a_go_mod(tmp_path: Path) -> None:
    from agent_audit_kit.scanners.supply_chain import _lockfile_canon

    assert _lockfile_canon("github.com/BurntSushi/toml", "go.mod") == "github.com/BurntSushi/toml"
    assert _lockfile_canon("Surreal_DB", "cargo.lock") == "surreal-db"
