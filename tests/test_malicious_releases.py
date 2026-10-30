"""AAK-MALICIOUS-RELEASE-001 and the offline feed it reads.

litellm 1.107.0 (OSV MAL-2026-2144) passed every rule on 0.6.27. These tests pin
the four places the rule reads a release (a pinned declaration, a lockfile, an
installed dist-info, an image digest), what does not match (the safe 1.106.2, a
pre-release, a range, a tag), that a scan never touches the network, the
cached-then-bundled load order, and `aak update`'s rebuild: atomic, MAL- records
only, the old cache kept on failure. Every fixture is a version string, a fake
dist-info folder or a digest; nothing is fetched.
"""

from __future__ import annotations

import http.client
import io
import json
import socket
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit import malicious_feed
from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.output.console import format_results as console_results
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.malicious_releases import scan

FIXTURES = Path(__file__).parent / "fixtures" / "malicious_releases"
RULE = "AAK-MALICIOUS-RELEASE-001"
DIGEST = "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"


def _found(root: Path) -> set[tuple[str, int | None]]:
    findings, _ = scan(root)
    assert all(f.rule_id == RULE for f in findings)
    return {(f.file_path, f.line_number) for f in findings}


def _cached_feed(entries: list[dict], oci: list[dict] | None = None) -> Path:
    path = malicious_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated_at": "2026-10-28T00:00:00Z", "source": "test feed", "entries": entries, "oci": oci or [],
    }))
    return path


def _entry(name: str, ecosystem: str = "PyPI", **extra: object) -> dict:
    return {"id": f"MAL-TEST-{name}", "aliases": [], "ecosystem": ecosystem, "name": name,
            "versions": [], "modified": "", "url": "", **extra}


# ---- the fixtures ----------------------------------------------------------------------


def test_each_place_a_release_is_read_fires() -> None:
    assert _found(FIXTURES / "firing") == {
        ("requirements.txt", 1),
        ("uv.lock", 5),
        ("lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA", 3),
        ("docker-compose.yml", 3),
    }


def test_the_evidence_names_the_feed_id_and_the_feed() -> None:
    findings, _ = scan(FIXTURES / "firing")
    for finding in findings:
        assert "MAL-2026-2144" in finding.evidence or "LITELLM-2026-10-21" in finding.evidence
        assert "bundled copy generated" in finding.evidence
        assert finding.severity is Severity.CRITICAL


def test_the_vendors_safe_pin_does_not_fire() -> None:
    assert _found(FIXTURES / "negative") == set()


def test_a_tag_without_a_digest_does_not_fire() -> None:
    assert _found(FIXTURES / "tag-only") == set()
    tagged = run_scan(project_root=FIXTURES / "tag-only")
    assert RULE not in {f.rule_id for f in tagged.findings}


def test_a_scan_never_touches_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a scan opened a network connection")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    result = run_scan(project_root=FIXTURES / "firing")
    assert len([f for f in result.findings if f.rule_id == RULE]) == 4
    assert not [f for f in result.findings if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL"]


def test_the_rule_is_critical() -> None:
    assert RULES[RULE].severity is Severity.CRITICAL


# ---- what matches ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line, fires",
    [
        ("litellm==1.107.0", True),
        ("litellm==1.107", True),        # PEP 440: 1.107 is 1.107.0
        ("LiteLLM[proxy]==1.82.8", True),
        ("litellm===1.82.7", True),
        ("litellm==1.107.0rc1", False),  # OSV: the release candidates are not affected
        ("litellm==1.106.2", False),
        ("litellm>=1.107.0", False),      # a range says nothing about what was installed
        ("litellm", False),
    ],
)
def test_a_requirement_matches_only_an_exact_listed_version(tmp_path: Path, line: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(line + "\n")
    assert bool(_found(tmp_path)) is fires


def test_an_every_version_entry_matches_any_declaration(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-typosquat", all_versions=True)])
    (tmp_path / "requirements.txt").write_text("aak_typosquat>=0.1\n")
    assert _found(tmp_path) == {("requirements.txt", 1)}


def test_npm_lockfiles_ranges_and_the_security_placeholder(tmp_path: Path) -> None:
    _cached_feed([
        _entry("aak-evil", "npm", all_versions=True),
        _entry("aak-ranged", "npm", ranges=[{"introduced": "1.2.0", "fixed": "1.3.0"}]),
    ])
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"},
        "node_modules/aak-evil": {"version": "0.0.1-security"},
        "node_modules/aak-ranged": {"version": "1.2.5"},
    }}, indent=2))
    findings, _ = scan(tmp_path)
    assert [("aak-ranged" in f.evidence, f.line_number) for f in findings] == [(True, 10)]


def test_an_mcp_config_launch_and_package_json_are_read(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-evil", "npm", versions=["1.0.0"])])
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"x": {"command": "npx", "args": ["-y", "aak-evil@1.0.0"]}}}, indent=2))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"aak-evil": "1.0.0"}}, indent=2))
    assert {path for path, _ in _found(tmp_path)} == {".mcp.json", "package.json"}


def test_a_program_run_by_name_names_no_registry(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-evil", "npm", all_versions=True)])
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {"command": "aak-evil"}}}))
    assert _found(tmp_path) == set()


def test_poetry_and_pipfile_lockfiles_are_read(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "litellm"\nversion = "1.82.7"\n')
    (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"litellm": {"version": "==1.82.8"}}}, indent=2))
    assert {path for path, _ in _found(tmp_path)} == {"poetry.lock", "Pipfile.lock"}


def test_a_digest_in_a_comment_is_not_a_deployment(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(f"services:\n  a:\n    # was litellm/litellm@{DIGEST}\n    image: x:1\n")
    assert _found(tmp_path) == set()


def test_a_digest_matches_under_any_registry_name(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM ghcr.io/berriai/litellm@{DIGEST}\n")
    assert _found(tmp_path) == {("Dockerfile", 1)}


# ---- the feed and its load order ------------------------------------------------------------


def test_the_bundled_feed_holds_what_osv_and_the_vendor_published() -> None:
    data = json.loads(malicious_feed.BUNDLED_FEED.read_text())
    (entry,) = data["entries"]
    assert (entry["id"], entry["ecosystem"], entry["name"]) == ("MAL-2026-2144", "PyPI", "litellm")
    assert entry["versions"] == ["1.82.7", "1.82.8", "1.107.0"]
    assert entry["modified"] == "2026-10-21T22:01:01.881791175Z"
    (image,) = data["oci"]
    assert image["digests"] == [DIGEST] and len(DIGEST) == len("sha256:") + 64


def test_the_cached_feed_is_read_first_and_a_broken_one_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("aak-cached-only==1.0.0\n")
    _cached_feed([_entry("aak-cached-only", versions=["1.0.0"])])
    assert malicious_feed.load_feed().origin == "cached"
    assert _found(tmp_path) == {("requirements.txt", 1)}
    malicious_feed.cache_path().write_text("{ not json")
    assert malicious_feed.load_feed().origin == "bundled"
    assert _found(tmp_path) == set()


def test_reports_name_the_feed_copy_and_its_age() -> None:
    result = run_scan(project_root=FIXTURES / "negative")
    feed = result.data_feeds["maliciousReleases"]
    assert feed["origin"] == "bundled" and feed["generatedAt"]
    sarif = json.loads(format_results(result))
    assert sarif["runs"][0]["properties"]["dataFeeds"]["maliciousReleases"]["generatedAt"] == feed["generatedAt"]
    assert f"Malicious-release feed: bundled copy, generated {feed['generatedAt']}" in console_results(result)


def test_an_empty_scan_result_has_no_feed_note() -> None:
    sarif = json.loads(format_results(ScanResult()))
    assert "properties" not in sarif["runs"][0]


# ---- `aak update`: rebuilding the cached feed ----------------------------------------------------


def _export(records: dict[str, dict]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, record in records.items():
            archive.writestr(f"{name}.json", json.dumps(record))
    return buffer.getvalue()


_PYPI = {
    "MAL-2026-1": {"id": "MAL-2026-1", "modified": "m", "affected": [{"package": {"ecosystem": "PyPI", "name": "aak-one"},
                                                                       "versions": ["1.0"]}]},
    "MAL-2026-2": {"id": "MAL-2026-2", "withdrawn": "2026-01-01", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-gone"}, "versions": ["1.0"]}]},
    "GHSA-xxxx-xxxx-xxxx": {"id": "GHSA-xxxx-xxxx-xxxx", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-not-malware"}, "versions": ["1.0"]}]},
}
_NPM = {
    "MAL-2026-3": {"id": "MAL-2026-3", "aliases": ["GHSA-aaaa-bbbb-cccc"], "affected": [
        {"package": {"ecosystem": "npm", "name": "aak-squat"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
    "MAL-2026-4": {"id": "MAL-2026-4", "affected": [
        {"package": {"ecosystem": "npm", "name": "aak-ranged"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "1.3.0"}]}]}]},
}


class _Response(io.BytesIO):
    def __init__(self, body: bytes, link: str = "") -> None:
        super().__init__(body)
        self.headers = {"Link": link}


def _opener(fail_on: str | None = None, github: list[tuple[list, str]] | None = None):
    pages = list(github or [])

    def opener(request: urllib.request.Request, timeout: float | None = None) -> _Response:
        url = request.full_url
        if fail_on and fail_on in url:
            raise urllib.error.URLError("network unreachable (test)")
        if url.endswith("/PyPI/all.zip"):
            return _Response(_export(_PYPI))
        if url.endswith("/npm/all.zip"):
            return _Response(_export(_NPM))
        if url.startswith("https://api.github.com/advisories"):
            body, link = pages.pop(0)
            return _Response(json.dumps(body).encode(), link)
        raise AssertionError(url)

    return opener


NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def test_refresh_keeps_only_mal_records_and_carries_the_bundled_digests() -> None:
    done = malicious_feed.refresh(opener=_opener(), now=NOW)
    data = json.loads(done.path.read_text())
    assert data["generated_at"] == "2026-10-28T12:00:00Z"
    assert sorted(e["id"] for e in data["entries"]) == ["MAL-2026-1", "MAL-2026-2144", "MAL-2026-3", "MAL-2026-4"]
    assert data["oci"][0]["digests"] == [DIGEST]
    assert done.counts == {"OSV PyPI": 1, "OSV npm": 2, "bundled": 1}
    feed = malicious_feed.load_feed()
    assert feed.origin == "cached"
    assert feed.match("npm", "aak-squat", "9.9.9") and feed.match("npm", "aak-ranged", "1.2.5")
    assert not feed.match("npm", "aak-ranged", "1.3.0")
    assert not list(done.path.parent.glob(".osv-export-*")) and not list(done.path.parent.glob(".malicious-*"))


def test_refresh_reads_github_malware_advisories_with_a_token() -> None:
    first = [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "vulnerabilities": [  # already in OSV under an alias
        {"package": {"ecosystem": "npm", "name": "aak-squat"}, "vulnerable_version_range": ">= 0"}]}]
    second = [{"ghsa_id": "GHSA-dddd-eeee-ffff", "identifiers": [{"type": "GHSA", "value": "GHSA-dddd-eeee-ffff"}],
               "updated_at": "u", "html_url": "https://github.com/advisories/GHSA-dddd-eeee-ffff",
               "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "aak-gh"},
                                    "vulnerable_version_range": "= 2.0.0"}]}]
    pages = [
        (first, '<https://api.github.com/advisories?type=malware&ecosystem=npm&after=X>; rel="next"'),
        ([], ""),
        (second, ""),
    ]
    done = malicious_feed.refresh(github_token="test-token", opener=_opener(github=pages), now=NOW)
    assert done.github == "read" and done.counts["GitHub"] == 1
    assert malicious_feed.load_feed().match("PyPI", "aak-gh", "2.0.0")


@pytest.mark.parametrize("fail_on", ["/PyPI/all.zip", "/npm/all.zip"])
def test_a_failed_refresh_keeps_the_old_cache_and_writes_nothing(fail_on: str) -> None:
    old = _cached_feed([_entry("aak-old", versions=["1.0"])])
    before = old.read_bytes()
    with pytest.raises(malicious_feed.FeedUpdateError):
        malicious_feed.refresh(opener=_opener(fail_on=fail_on), now=NOW)
    assert old.read_bytes() == before
    assert sorted(p.name for p in old.parent.iterdir()) == ["malicious_releases.json"]


def test_aak_update_exits_non_zero_when_the_feed_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **_: (_ for _ in ()).throw(
        malicious_feed.FeedUpdateError("URLError: offline")))
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "0"])
    assert result.exit_code == 2
    assert "feed update failed: URLError: offline" in result.output
    assert "bundled feed" in result.output


def test_aak_update_reports_what_it_wrote(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed.urllib.request, "urlopen", _opener())
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "0"])
    assert result.exit_code == 0, result.output
    assert "Malicious-release feed updated: 4 entries" in result.output
    assert "GitHub: skipped" in result.output


def test_github_malware_needs_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **_: pytest.fail("refreshed without a token"))
    result = CliRunner().invoke(cli, ["update", "--github-malware", "--nvd-days", "0"])
    assert result.exit_code == 2 and "needs GITHUB_TOKEN or GH_TOKEN" in result.output


def test_a_token_alone_does_not_page_github(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    seen: dict[str, object] = {}
    monkeypatch.setattr(vuln_db, "update_database", lambda: 1)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **kw: seen.update(kw) or malicious_feed.Refreshed(
        Path("feed.json"), "t", {}, "skipped"))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    assert CliRunner().invoke(cli, ["update", "--nvd-days", "0"]).exit_code == 0
    assert seen["github_token"] is None
    assert CliRunner().invoke(cli, ["update", "--github-malware", "--nvd-days", "0"]).exit_code == 0
    assert seen["github_token"] == "test-token"
    assert set(seen) == {"github_token", "on_record"}  # the advisory feed reads the same downloads


def test_a_lockfile_repeating_one_release_reports_it_once(tmp_path: Path) -> None:
    """One finding per release a lockfile resolves, at its first entry: 300,000 copies of
    one entry made 300,000 findings."""
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "litellm"\nversion = "1.107.0"\n' * 3)
    findings = [f for f in scan(tmp_path)[0] if f.rule_id == RULE]
    assert [(f.file_path, f.line_number) for f in findings] == [("uv.lock", 2)]
