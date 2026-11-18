"""scripts/refresh_bundled_malicious.py: takeovers into the bundled feed, typosquats out.

The bundled malicious-release feed lists established packages that were taken
over. The script reads GitHub's malware advisories of the last few days and keeps
a package only when its registry shows a release at least 30 days older than the
advisory that the advisory does not list. Every network call goes through the
opener these tests pass; nothing is fetched, and the clock is pinned.
"""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import malicious_feed

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 20, 5, 29, tzinfo=timezone.utc)
PUBLISHED = NOW - timedelta(days=1)


def _load_script() -> Any:
    spec = importlib.util.spec_from_file_location("refresh_bundled_malicious", REPO / "scripts" / "refresh_bundled_malicious.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = _load_script()


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _advisory(ghsa: str, ecosystem: str, name: str, *specs: str, references: tuple[str, ...] = ()) -> dict:
    return {
        "ghsa_id": ghsa, "published_at": _iso(PUBLISHED), "updated_at": _iso(PUBLISHED),
        "html_url": f"https://github.com/advisories/{ghsa}", "withdrawn_at": None,
        "identifiers": [{"type": "GHSA", "value": ghsa}], "references": list(references),
        "vulnerabilities": [{"package": {"ecosystem": ecosystem, "name": name}, "vulnerable_version_range": s}
                            for s in specs],
    }


def _osv(ident: str, ecosystem: str, name: str, versions: list[str], aliases: list[str] | None = None) -> dict:
    return {"id": ident, "modified": "2026-11-19T01:02:03.456789123Z", "aliases": aliases or [],
            "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "versions": versions}]}


class _Response(io.BytesIO):
    def __init__(self, body: Any, link: str = "") -> None:
        super().__init__(body if isinstance(body, bytes) else json.dumps(body).encode())
        self.headers = {"Link": link}


class Network:
    """The stub opener: GitHub pages per ecosystem, registry documents by URL, OSV
    records by package; anything else, or a URL in `refuse`, fails the test."""

    def __init__(self, advisories: dict[str, list[dict]] | None = None, registry: dict[str, Any] | None = None,
                 osv: dict[str, list[dict]] | None = None, refuse: tuple[str, ...] = ()) -> None:
        self.advisories = advisories or {}
        self.registry = registry or {}
        self.osv = osv or {}
        self.refuse = refuse
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float | None = None) -> _Response:
        self.requests.append(request)
        url = request.full_url
        if any(url.startswith(prefix) for prefix in self.refuse):
            raise AssertionError(f"unexpected request: {url}")
        if url.startswith("https://api.github.com/advisories?"):
            ecosystem = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["ecosystem"][0]
            return _Response(self.advisories.get(ecosystem, []))
        if url == script.OSV_QUERY:
            package = json.loads(request.data)["package"]
            return _Response({"vulns": self.osv.get(package["name"], [])})
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            ident = url.rsplit("/", 1)[1]
            return _Response(next(r for rs in self.osv.values() for r in rs if r["id"] == ident))
        if url in self.registry:
            body = self.registry[url]
            if isinstance(body, BaseException):
                raise body
            if body is None:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
            return _Response(body)
        raise AssertionError(f"unexpected request: {url}")


def _pypi(name: str, **releases: datetime) -> tuple[str, dict]:
    return (f"https://pypi.org/pypi/{name}/json",
            {"releases": {v.replace("_", "."): [{"upload_time_iso_8601": _iso(t)}] for v, t in releases.items()}})


def _npm(name: str, times: dict[str, datetime]) -> tuple[str, dict]:
    stamps = {"created": _iso(min(times.values())), "modified": _iso(NOW), **{v: _iso(t) for v, t in times.items()}}
    return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}", {"time": stamps}


@pytest.fixture
def feed(tmp_path: Path) -> Path:
    """A copy of the bundled feed, so a run never writes the checkout's."""
    path = tmp_path / "malicious_releases.json"
    shutil.copyfile(malicious_feed.BUNDLED_FEED, path)
    return path


def _takeover_network(**extra: Any) -> Network:
    """agent-framework's shape: a release two years before the advisory, then two
    malicious ones the advisory lists, and an OSV record that does not alias the
    GHSA but that the advisory's references name."""
    ghsa = "GHSA-aaaa-bbbb-0001"
    advisory = _advisory(ghsa, "pip", "aak-established", "= 2.0.1", "= 2.0.2", references=(
        "https://github.com/ossf/malicious-packages/blob/abc/osv/malicious/pypi/aak-established/MAL-2026-90001.json",))
    url, doc = _pypi("aak-established", **{"1_0_0": NOW - timedelta(days=730), "2_0_1": PUBLISHED,
                                           "2_0_2": PUBLISHED})
    return Network(advisories={"pip": [advisory], **extra.pop("advisories", {})},
                   registry={url: doc, **extra.pop("registry", {})},
                   osv={"aak-established": [_osv("MAL-2026-90001", "PyPI", "aak-established", ["2.0.2", "2.0.1"])],
                        **extra.pop("osv", {})})


# ---- what is kept and what is dropped -------------------------------------------------------


def test_a_takeover_of_an_established_package_is_kept(feed: Path) -> None:
    before = feed.read_text()
    outcome = script.refresh_bundled(feed, opener=_takeover_network(), now=NOW, days=3)
    [decision] = outcome.decisions
    assert decision.outcome == "kept", decision
    assert decision.reason.startswith("1.0.0 was released 2024-11-20; MAL-2026-90001 lists 2.0.1, 2.0.2")
    data = json.loads(feed.read_text())
    assert data["entries"][-1] == {
        "id": "MAL-2026-90001", "aliases": ["GHSA-aaaa-bbbb-0001"], "ecosystem": "PyPI", "name": "aak-established",
        "versions": ["2.0.1", "2.0.2"], "modified": "2026-11-19T01:02:03.456789123Z",
        "url": "https://osv.dev/vulnerability/MAL-2026-90001",
    }
    assert data["generated_at"] == "2026-11-20T05:29:00Z"
    original = json.loads(before)
    assert data["source"].startswith(original["source"])
    assert data["source"].endswith(
        "On 2026-11-20, scripts/refresh_bundled_malicious.py added MAL-2026-90001, takeovers of established "
        "packages among GitHub's malware advisories published since 2026-11-17, each as "
        "https://api.osv.dev/v1/vulns/<id> gave it (the GitHub advisory where OSV had no record).")
    # Every other byte is kept: the old file with the two header values replaced is
    # the new file without the inserted entries, which go at the end of `entries`.
    headed = before.replace(json.dumps(original["generated_at"]), json.dumps(data["generated_at"]), 1).replace(
        json.dumps(original["source"]), json.dumps(data["source"]), 1)
    close = headed.index("\n  ]", headed.index('"entries": ['))
    after = feed.read_text()
    assert after.startswith(headed[:close] + ",\n    {") and after.endswith(headed[close:])
    assert malicious_feed.parse_feed(data, "bundled", feed).match("PyPI", "aak-established", "2.0.2")


def test_a_package_whose_only_releases_are_the_malicious_ones_is_dropped(feed: Path) -> None:
    advisory = _advisory("GHSA-aaaa-bbbb-0002", "npm", "aak-squat", "= 1.0.0", "= 1.0.1")
    url, doc = _npm("aak-squat", {"1.0.0": PUBLISHED - timedelta(days=2), "1.0.1": PUBLISHED - timedelta(days=1)})
    network = Network(advisories={"npm": [advisory]}, registry={url: doc}, refuse=("https://api.osv.dev",))
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    [decision] = outcome.decisions
    assert (decision.outcome, decision.reason) == (
        "dropped", "no release at least 30 days before the advisory outside the versions it lists (2 on the registry)")
    assert not outcome.written and outcome.added == []


def test_a_young_clean_release_does_not_establish_the_package(feed: Path) -> None:
    advisory = _advisory("GHSA-aaaa-bbbb-0003", "npm", "aak-young", "= 2.0.0")
    url, doc = _npm("aak-young", {"1.0.0": PUBLISHED - timedelta(days=29), "2.0.0": PUBLISHED})
    outcome = script.refresh_bundled(feed, opener=Network(advisories={"npm": [advisory]}, registry={url: doc}), now=NOW)
    assert [d.outcome for d in outcome.decisions] == ["dropped"]


def test_an_every_version_advisory_is_dropped_without_a_registry_request(feed: Path) -> None:
    advisory = _advisory("GHSA-aaaa-bbbb-0004", "npm", "aak-typo", ">= 0")
    network = Network(advisories={"npm": [advisory]}, refuse=("https://registry.npmjs.org", "https://api.osv.dev"))
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert decision.outcome == "dropped" and "every version (>= 0)" in decision.reason


def test_a_package_the_registry_no_longer_serves_is_dropped(feed: Path) -> None:
    advisory = _advisory("GHSA-aaaa-bbbb-0005", "pip", "aak-removed", "= 99.99.1")
    network = Network(advisories={"pip": [advisory]}, registry={"https://pypi.org/pypi/aak-removed/json": None})
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert (decision.outcome, decision.reason) == ("dropped", "the registry does not serve the package (404)")


def test_npm_security_placeholders_never_establish_a_package(feed: Path) -> None:
    advisory = _advisory("GHSA-aaaa-bbbb-0006", "npm", "aak-held", "= 1.0.0")
    old = PUBLISHED - timedelta(days=60)
    url, doc = _npm("aak-held", {"1.0.0": PUBLISHED, "0.0.1-security": old, "0.0.1-security.0": old})
    outcome = script.refresh_bundled(feed, opener=Network(advisories={"npm": [advisory]}, registry={url: doc}), now=NOW)
    assert [d.outcome for d in outcome.decisions] == ["dropped"]


def test_a_package_with_no_osv_record_is_written_from_the_advisory(feed: Path) -> None:
    advisory = _advisory("GHSA-aaaa-bbbb-0007", "npm", "@aak/held-over", "= 3.1.4")
    url, doc = _npm("@aak/held-over", {"3.0.0": NOW - timedelta(days=900), "3.1.4": PUBLISHED})
    assert url == "https://registry.npmjs.org/@aak%2Fheld-over"
    network = Network(advisories={"npm": [advisory]}, registry={url: doc})
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    [entry] = outcome.added
    assert (entry["id"], entry["url"], entry["name"], entry["versions"]) == (
        "GHSA-aaaa-bbbb-0007", "https://github.com/advisories/GHSA-aaaa-bbbb-0007", "@aak/held-over", ["3.1.4"])


def test_the_osv_record_is_matched_by_alias(feed: Path) -> None:
    ghsa = "GHSA-aaaa-bbbb-0008"
    advisory = _advisory(ghsa, "npm", "aak-pkg", "= 5.0.0")
    url, doc = _npm("aak-pkg", {"4.0.0": NOW - timedelta(days=400), "5.0.0": PUBLISHED})
    records = [_osv("MAL-2026-80001", "npm", "aak-pkg", ["4.9.9"]),          # another incident on the package
               _osv("MAL-2026-80002", "npm", "aak-pkg", ["5.0.0"], aliases=[ghsa])]
    outcome = script.refresh_bundled(
        feed, opener=Network(advisories={"npm": [advisory]}, registry={url: doc}, osv={"aak-pkg": records}), now=NOW)
    [entry] = outcome.added
    assert (entry["id"], entry["aliases"], entry["versions"]) == ("MAL-2026-80002", [ghsa], ["5.0.0"])


def test_an_existing_entry_survives_a_run(feed: Path) -> None:
    before = json.loads(feed.read_text())["entries"]
    # An advisory the feed already holds under an alias (axios, GHSA-fw8c-xr5c-95f9) is not
    # read again, and one new takeover is appended after every existing entry.
    axios = _advisory("GHSA-fw8c-xr5c-95f9", "npm", "axios", "= 1.14.1", "= 0.30.4")
    outcome = script.refresh_bundled(feed, opener=_takeover_network(advisories={"npm": [axios]}), now=NOW)
    assert [(d.name, d.outcome, d.reason) for d in outcome.decisions if d.name == "axios"] == [
        ("axios", "skipped", "already bundled")]
    after = json.loads(feed.read_text())["entries"]
    assert after[:len(before)] == before and [e["id"] for e in after[len(before):]] == ["MAL-2026-90001"]
    # A second run over the same advisories adds nothing and leaves the file as it is.
    text = feed.read_text()
    again = script.refresh_bundled(feed, opener=_takeover_network(), now=NOW + timedelta(hours=1))
    assert [d.outcome for d in again.decisions] == ["skipped"] and not again.written
    assert feed.read_text() == text


def test_no_change_leaves_the_file_untouched(feed: Path) -> None:
    stat, text = feed.stat(), feed.read_bytes()
    network = Network(advisories={"npm": [_advisory("GHSA-aaaa-bbbb-0009", "npm", "aak-typo", ">= 0")]})
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    assert not outcome.written
    assert feed.read_bytes() == text and feed.stat().st_mtime_ns == stat.st_mtime_ns
    assert not list(feed.parent.glob("*.tmp"))


def test_a_failed_lookup_is_an_error_and_the_rest_is_still_written(feed: Path) -> None:
    broken = _advisory("GHSA-aaaa-bbbb-0010", "npm", "aak-flaky", "= 1.0.0")
    network = _takeover_network(advisories={"npm": [broken]}, registry={
        "https://registry.npmjs.org/aak-flaky": urllib.error.URLError("timed out (test)")})
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    assert sorted((d.name, d.outcome) for d in outcome.decisions) == [("aak-established", "kept"), ("aak-flaky", "error")]
    assert outcome.written and [e["id"] for e in outcome.added] == ["MAL-2026-90001"]


def test_a_failed_listing_writes_nothing(feed: Path) -> None:
    text = feed.read_text()

    def opener(request: urllib.request.Request, timeout: float | None = None) -> None:
        raise urllib.error.URLError("network unreachable (test)")

    with pytest.raises(script.RefreshError):
        script.refresh_bundled(feed, opener=opener, now=NOW)
    assert feed.read_text() == text


def test_the_listing_reads_the_window_and_sends_the_token_only_to_github(feed: Path) -> None:
    network = _takeover_network()
    script.refresh_bundled(feed, opener=network, now=NOW, days=3, token="not-a-real-credential")
    listing = [r for r in network.requests if r.full_url.startswith("https://api.github.com/")]
    assert [urllib.parse.parse_qs(urllib.parse.urlsplit(r.full_url).query)["ecosystem"][0] for r in listing] == [
        "pip", "npm", "rust", "go"]
    assert all("published=%3E%3D2026-11-17" in r.full_url and "type=malware" in r.full_url for r in listing)
    assert all((r.get_header("Authorization") or "").endswith(" not-a-real-credential") for r in listing)
    assert not [r for r in network.requests if r not in listing and r.get_header("Authorization")]


@pytest.mark.parametrize(
    "ecosystem, specs, version, expected",
    [
        ("PyPI", ["= 1.26.2", "= 1.26.1"], "1.26.0", False),
        ("PyPI", ["= 1.26.2"], "1.26.2.0", True),          # PEP 440: the same release
        ("npm", [">= 0"], "0.0.1", True),
        ("npm", [">= 1.0.0, < 1.2.0"], "1.1.9", True),
        ("npm", [">= 1.0.0, < 1.2.0"], "1.2.0", False),
        ("npm", ["> 1.0.0, <= 1.2.0"], "1.0.0", False),
        ("npm", ["> 1.0.0, <= 1.2.0"], "1.2.0", True),
        ("npm", ["~ 1.0.0"], "9.9.9", True),               # unreadable: counts as listed
        ("npm", ["< 2.0.0"], "not-a-version", True),       # cannot be ordered: counts as listed
    ],
)
def test_which_versions_an_advisory_lists(ecosystem: str, specs: list[str], version: str, expected: bool) -> None:
    assert script.listed(ecosystem, specs, version) is expected


# ---- the committed bundled feed ----------------------------------------------------------------


def test_every_bundled_entry_is_read_and_the_added_ones_have_the_takeover_shape() -> None:
    data = json.loads(malicious_feed.BUNDLED_FEED.read_text())
    entries = data["entries"]
    assert len({e["id"] for e in entries}) == len(entries)
    assert malicious_feed.parse_feed(data, "bundled", malicious_feed.BUNDLED_FEED).entry_count == len(entries)
    for entry in entries[7:]:  # after the seven hand-picked entries: the script's
        assert entry["id"] in data["source"], entry["id"]
        assert entry["versions"] and not entry.get("all_versions") and not entry.get("ranges"), entry["id"]
        assert any(a.startswith("GHSA-") for a in [entry["id"], *entry["aliases"]]), entry["id"]
        assert entry["url"] in (f"https://osv.dev/vulnerability/{entry['id']}",
                                f"https://github.com/advisories/{entry['id']}")
    assert malicious_feed.parse_generated_at(data["generated_at"]) is not None
