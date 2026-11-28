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
import re
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
NOW_TEXT = "2026-11-20T05:29:00Z"
PUBLISHED = NOW - timedelta(days=1)
#: The line `checked_at` is written on, newline before it included.
_CHECKED_LINE = re.compile(r'\n[ \t]*"checked_at": "[^"\n]*",')


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
    """A copy of the bundled feed, so a run never writes the checkout's, with the
    `checked_at` a refresh leaves in it taken out: the tests below say what the first
    check writes, and the checkout's own file says it already after one refresh."""
    path = tmp_path / "malicious_releases.json"
    text = malicious_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    path.write_text(_CHECKED_LINE.sub("", text, count=1), encoding="utf-8")
    assert "checked_at" not in json.loads(path.read_text(encoding="utf-8"))
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
    assert data["generated_at"] == data["checked_at"] == "2026-11-20T05:29:00Z"
    original = json.loads(before)
    assert data["source"].startswith(original["source"])
    assert data["source"].endswith(
        "On 2026-11-20, scripts/refresh_bundled_malicious.py added MAL-2026-90001, takeovers of established "
        "packages and malicious agent, MCP and model-runtime packages among GitHub's malware advisories "
        "published since "
        "2026-11-17, each as "
        "https://api.osv.dev/v1/vulns/<id> gave it (the GitHub advisory where OSV had no record).")
    # Every other byte is kept: the old file with the two header values replaced, and
    # `checked_at` on the line after `generated_at`, is the new file without the
    # inserted entries, which go at the end of `entries`.
    generated_line = f'"generated_at": {json.dumps(original["generated_at"])},'
    headed = before.replace(
        generated_line, f'"generated_at": {json.dumps(data["generated_at"])},\n  "checked_at": {json.dumps(NOW_TEXT)},', 1,
    ).replace(json.dumps(original["source"]), json.dumps(data["source"]), 1)
    close = headed.index("\n  ]", headed.index('"entries": ['))
    after = feed.read_text()
    assert after.startswith(headed[:close] + ",\n    {") and after.endswith(headed[close:])
    assert malicious_feed.parse_feed(data, "bundled", feed).match("PyPI", "aak-established", "2.0.2")


def test_a_takeover_into_a_feed_that_was_checked_before_replaces_checked_at(feed: Path) -> None:
    """The bundled file after its first refresh: `checked_at` is there already, so a
    run that keeps a package replaces its value and writes no second line. The tests
    above used to read the checkout's own file as one never checked, and failed on
    the first refresh that was to be merged (2026-11-25)."""
    earlier = "2026-11-19T05:29:00Z"
    quiet = Network(advisories={"npm": [_advisory("GHSA-aaaa-bbbb-0009", "npm", "aak-typo", ">= 0")]})
    script.refresh_bundled(feed, opener=quiet, now=NOW - timedelta(days=1))
    before = feed.read_text(encoding="utf-8")
    assert json.loads(before)["checked_at"] == earlier
    outcome = script.refresh_bundled(feed, opener=_takeover_network(), now=NOW, days=3)
    assert outcome.written and outcome.checked
    after, original = feed.read_text(encoding="utf-8"), json.loads(before)
    data = json.loads(after)
    assert after.count('"checked_at"') == 1
    assert data["checked_at"] == data["generated_at"] == NOW_TEXT
    assert data["entries"][:-1] == original["entries"] and data["entries"][-1]["id"] == "MAL-2026-90001"
    headed = (
        before.replace(f'"checked_at": "{earlier}"', f'"checked_at": "{NOW_TEXT}"', 1)
        .replace(f'"generated_at": {json.dumps(original["generated_at"])}', f'"generated_at": "{NOW_TEXT}"', 1)
        .replace(json.dumps(original["source"]), json.dumps(data["source"]), 1)
    )
    close = headed.index("\n  ]", headed.index('"entries": ['))
    assert after.startswith(headed[:close] + ",\n    {") and after.endswith(headed[close:])


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
    # A second run over the same advisories adds nothing: only `checked_at` moves.
    text = feed.read_text()
    again = script.refresh_bundled(feed, opener=_takeover_network(), now=NOW + timedelta(hours=1))
    assert [d.outcome for d in again.decisions] == ["skipped"] and not again.written and again.checked
    assert feed.read_text() == text.replace(NOW_TEXT, "2026-11-20T06:29:00Z").replace(
        '"generated_at": "2026-11-20T06:29:00Z"', f'"generated_at": {json.dumps(NOW_TEXT)}', 1)


def test_no_change_leaves_every_byte_but_checked_at(feed: Path) -> None:
    """A quiet day adds no entry: `generated_at`, `source` and every entry stay as
    they were, and only `checked_at` records the check (2026-11-21: three quiet days
    made a bundled copy checked that morning read as stale)."""
    before = feed.read_text()
    network = Network(advisories={"npm": [_advisory("GHSA-aaaa-bbbb-0009", "npm", "aak-typo", ">= 0")]})
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    assert not outcome.written and outcome.checked
    original, data = json.loads(before), json.loads(feed.read_text())
    assert data == {**original, "checked_at": NOW_TEXT}
    line = f'"generated_at": {json.dumps(original["generated_at"])},'
    assert feed.read_text() == before.replace(line, line + f'\n  "checked_at": {json.dumps(NOW_TEXT)},', 1)
    assert not list(feed.parent.glob("*.tmp"))


def test_checked_at_moves_on_each_full_check_and_not_on_a_failed_one(feed: Path) -> None:
    """`checked_at` is written once and replaced in place after; a run whose lookup
    failed checked nothing, so with nothing kept it leaves the file as it was."""
    quiet = Network(advisories={"npm": [_advisory("GHSA-aaaa-bbbb-0009", "npm", "aak-typo", ">= 0")]})
    script.refresh_bundled(feed, opener=quiet, now=NOW)
    first = feed.read_text()
    later = NOW + timedelta(days=1)
    assert script.refresh_bundled(feed, opener=quiet, now=later).checked
    assert feed.read_text() == first.replace(NOW_TEXT, later.strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert feed.read_text().count('"checked_at"') == 1
    text, stat = feed.read_text(), feed.stat()
    broken = Network(advisories={"npm": [_advisory("GHSA-aaaa-bbbb-0010", "npm", "aak-flaky", "= 1.0.0")]},
                     registry={"https://registry.npmjs.org/aak-flaky": urllib.error.URLError("timed out (test)")})
    outcome = script.refresh_bundled(feed, opener=broken, now=later + timedelta(days=1))
    assert [d.outcome for d in outcome.decisions] == ["error"] and not outcome.written and not outcome.checked
    assert feed.read_text() == text and feed.stat().st_mtime_ns == stat.st_mtime_ns
    dry = script.refresh_bundled(feed, opener=quiet, now=later + timedelta(days=2), dry_run=True)
    assert not dry.checked and feed.read_text() == text


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


def test_every_bundled_entry_is_read_and_the_added_ones_have_the_takeover_or_lane_shape() -> None:
    """A takeover lists its malicious releases, never every version or a range; a
    lane package may list every version, since it never had a clean release."""
    data = json.loads(malicious_feed.BUNDLED_FEED.read_text())
    entries = data["entries"]
    assert len({e["id"] for e in entries}) == len(entries)
    assert malicious_feed.parse_feed(data, "bundled", malicious_feed.BUNDLED_FEED).entry_count == len(entries)
    for entry in entries[7:]:  # after the seven hand-picked entries: the script's
        assert entry["id"] in data["source"], entry["id"]
        assert not entry.get("ranges"), entry["id"]
        if script.agent_lane(entry["ecosystem"], entry["name"]) is None:
            assert entry["versions"] and not entry.get("all_versions"), entry["id"]
        else:
            assert entry["versions"] or entry.get("all_versions") is True, entry["id"]
        assert any(a.startswith("GHSA-") for a in [entry["id"], *entry["aliases"]]), entry["id"]
        assert entry["url"] in (f"https://osv.dev/vulnerability/{entry['id']}",
                                f"https://github.com/advisories/{entry['id']}")
    assert malicious_feed.parse_generated_at(data["generated_at"]) is not None


# ---- the agent and MCP lane (2026-11-26) -----------------------------------------------------


AGENT, MODEL, SQUAT = "AGENT_LANE_TOKENS", "MODEL_LANE_TOKENS", "AGENT_HOST_DEPENDENCIES"


@pytest.mark.parametrize(("ecosystem", "name", "lane"), [
    ("npm", "@apexfdn/copilot-mcp", ("copilot", AGENT)),
    ("npm", "@guangnao/claude-cli", ("claude", AGENT)),
    ("npm", "create-ai-agent-setup", ("agent", AGENT)),
    ("PyPI", "mcp-diag-7f3a", ("mcp", AGENT)),
    ("PyPI", "glbl-agent", ("agent", AGENT)),
    ("PyPI", "Open_AI.Tools", None),         # `open` and `ai`, not `openai`
    ("PyPI", "openai-helpers", ("openai", AGENT)),
    ("Go", "github.com/acme/mcp-go", ("mcp", AGENT)),
    ("npm", "@skills/pack", ("skills", AGENT)),       # a scope token counts
    ("PyPI", "magentic-utils", None),         # whole tokens only, and no agent-token prefix
    ("npm", "reagent-lib", None),
    ("npm", "@prime0/ajjv", None),
    ("PyPI", "gpt-researcher", ("gpt-researcher", script.PIN_TABLES)),   # no token, but pinned
    # 2026-11-28: the model and runtime list, and agent-token typosquats.
    ("PyPI", "llama-index-tools-x", ("llama", MODEL)),
    ("npm", "tavern-ai-sdk", ("ai-sdk", MODEL)),      # `sdk` counts beside `ai`
    ("npm", "@ai-sdk/helpers", ("ai-sdk", MODEL)),
    ("npm", "acme-sdk", None),                         # and only there
    ("PyPI", "mlp-agent-qwen", ("agent", AGENT)),      # the agent list is read first
    ("npm", "openaii", ("openaii", SQUAT)),
    ("npm", "langchian", None),    # two edits from langchain, but no agent token starts it
    ("npm", "agentkeepalive-x", ("agentkeepalive", SQUAT)),
    ("npm", "agentkit", None),     # starts with `agent`, three or more edits from every name
])
def test_which_names_are_in_the_agent_lane(ecosystem: str, name: str, lane: tuple[str, str] | None) -> None:
    match = script.agent_lane(ecosystem, name)
    assert (match if match is None else (match.token, match.source)) == lane


# The 27 Nov 2026 malware advisories the order names, as GitHub listed them (the GHSA ids
# are test-only stand-ins: the real ones are in the bundled feed after the 28 Nov refresh).
MODEL_LANE_CASES = [
    ("pip", "vk-mlp-agent", "= 9999.0", "agent (AGENT_LANE_TOKENS)"),
    ("pip", "qwen-tts-runtime", "= 0.3.0", "qwen (MODEL_LANE_TOKENS)"),
    ("pip", "qwen-tts-cpu", "= 0.3.0", "qwen (MODEL_LANE_TOKENS)"),
    ("pip", "qwentts-gradio", "= 0.3.0", "qwentts (MODEL_LANE_TOKENS)"),
    ("pip", "qwenvox-tts-3", "= 0.3.0", "tts (MODEL_LANE_TOKENS)"),
    ("npm", "agentkpalive", ">= 0", "agentkpalive (AGENT_HOST_DEPENDENCIES; 2 edits from agentkeepalive)"),
    ("npm", "tavern-ai-sdk", "= 1.0.0", "ai-sdk (MODEL_LANE_TOKENS)"),
]


def test_the_27_nov_model_and_typosquat_names_are_kept_with_the_list_that_admitted_them(feed: Path) -> None:
    advisories: dict[str, list[dict]] = {"pip": [], "npm": []}
    for i, (ecosystem, name, spec, _lane) in enumerate(MODEL_LANE_CASES):
        advisories[ecosystem].append(_advisory(f"GHSA-test-0028-{i:04d}", ecosystem, name, spec))
    network = Network(advisories=advisories,
                      refuse=("https://pypi.org", "https://registry.npmjs.org"))
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    reasons = {d.name: (d.outcome, d.reason) for d in outcome.decisions}
    for _ecosystem, name, spec, lane in MODEL_LANE_CASES:
        assert reasons[name] == ("kept", f"agent lane: {lane}; the advisory lists {spec}"), name
    assert outcome.written and outcome.checked
    bundled = malicious_feed.parse_feed(json.loads(feed.read_text()), "bundled", feed)
    assert bundled.match("PyPI", "vk-mlp-agent", "9999.0") and bundled.match("PyPI", "qwen-tts-cpu", "0.3.0")
    assert bundled.match("npm", "agentkpalive", "1.0.0") and not bundled.match("PyPI", "qwen-tts-cpu", "0.2.0")


@pytest.mark.parametrize("name", ["magentic", "reagent", "waveferry", "toneharbor"])
def test_names_outside_both_lists_take_the_takeover_test(feed: Path, name: str) -> None:
    """waveferry and toneharbor are generic audio names from the same 27 Nov batch."""
    assert script.agent_lane("PyPI", name) is None
    network = Network(advisories={"pip": [_advisory("GHSA-aaaa-bbbb-0104", "pip", name, ">= 0")]},
                      refuse=("https://pypi.org", "https://api.osv.dev"))
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert decision.outcome == "dropped" and "every version (>= 0)" in decision.reason


@pytest.mark.parametrize(("a", "b", "distance"), [
    ("agentkpalive", "agentkeepalive", 2), ("openaii", "openai", 1), ("anthropic", "anthropic", 0),
    ("agentkit", "agentkeepalive", 3),   # past the limit of 2: reported as 3
    ("", "abc", 3), ("kitten", "sitting", 3),
])
def test_edit_distance(a: str, b: str, distance: int) -> None:
    assert script.edit_distance(a, b, 2) == min(distance, 3)


def _osv_every(ident: str, ecosystem: str, name: str, aliases: list[str]) -> dict:
    return {"id": ident, "modified": "2026-11-24T10:00:00Z", "aliases": aliases,
            "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}


def test_an_every_version_lane_package_is_kept_as_osv_lists_it(feed: Path) -> None:
    """@apexfdn/copilot-mcp (GHSA-8q2p-w9w5-552h, MAL-2026-20505): every version, and no
    registry request, since the takeover test is not asked."""
    ghsa = "GHSA-test-0000-0001"  # the real ids are in the bundled feed now
    network = Network(
        advisories={"npm": [_advisory(ghsa, "npm", "@apexfdn/copilot-mcp", ">= 0")]},
        osv={"@apexfdn/copilot-mcp": [_osv_every("MAL-2026-90505", "npm", "@apexfdn/copilot-mcp", [ghsa])]},
        refuse=("https://registry.npmjs.org",))
    outcome = script.refresh_bundled(feed, opener=network, now=NOW)
    [decision] = outcome.decisions
    assert (decision.outcome, decision.reason) == ("kept", "agent lane: copilot (AGENT_LANE_TOKENS); the advisory lists >= 0")
    entry = json.loads(feed.read_text())["entries"][-1]
    assert (entry["id"], entry["all_versions"], entry["versions"], entry["aliases"]) == (
        "MAL-2026-90505", True, [], [ghsa])
    feed_ = malicious_feed.parse_feed(json.loads(feed.read_text()), "bundled", feed)
    assert feed_.match("npm", "@apexfdn/copilot-mcp", "1.0.0") and outcome.checked


def test_a_lane_package_with_listed_versions_is_kept_without_the_registry(feed: Path) -> None:
    """@guangnao/claude-cli (GHSA-vfqh-3659-q56x): 1.0.0 to 1.0.17, every release it has."""
    ghsa = "GHSA-test-0000-0002"
    versions = [f"1.0.{i}" for i in range(18)]
    network = Network(
        advisories={"npm": [_advisory(ghsa, "npm", "@guangnao/claude-cli", "<= 1.0.17")]},
        osv={"@guangnao/claude-cli": [_osv("MAL-2026-93209", "npm", "@guangnao/claude-cli", versions, [ghsa])]},
        refuse=("https://registry.npmjs.org",))
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert (decision.outcome, decision.reason) == ("kept", "agent lane: claude (AGENT_LANE_TOKENS); the advisory lists <= 1.0.17")
    entry = json.loads(feed.read_text())["entries"][-1]
    assert entry["id"] == "MAL-2026-93209" and "all_versions" not in entry
    assert sorted(entry["versions"]) == sorted(versions)


def test_a_lane_package_with_no_osv_record_is_written_from_the_advisory(feed: Path) -> None:
    """create-ai-agent-setup (GHSA-4c46-v99r-6h9r): three listed releases, no OSV record."""
    ghsa = "GHSA-test-0000-0003"
    network = Network(advisories={"npm": [_advisory(
        ghsa, "npm", "create-ai-agent-setup", "= 2.0.0-alpha.0", "= 2.0.0", "= 2.1.0")]},
        refuse=("https://registry.npmjs.org",))
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert decision.outcome == "kept" and decision.reason.startswith("agent lane: agent (AGENT_LANE_TOKENS);")
    entry = json.loads(feed.read_text())["entries"][-1]
    assert (entry["id"], entry["versions"], entry["url"]) == (
        ghsa, ["2.0.0", "2.0.0-alpha.0", "2.1.0"], f"https://github.com/advisories/{ghsa}")


def test_a_lane_record_listing_every_version_is_narrowed_to_the_advisory(feed: Path) -> None:
    """A lane package whose advisory lists some versions keeps those, never OSV's
    every version: an established lane package taken over still has clean releases."""
    ghsa = "GHSA-aaaa-bbbb-0101"
    network = Network(
        advisories={"pip": [_advisory(ghsa, "pip", "aak-mcp-old", "= 3.1.0")]},
        osv={"aak-mcp-old": [_osv_every("MAL-2026-90101", "PyPI", "aak-mcp-old", [ghsa])]})
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    entry = json.loads(feed.read_text())["entries"][-1]
    assert decision.outcome == "kept"
    assert (entry["id"], entry["versions"], entry.get("all_versions")) == (ghsa, ["3.1.0"], None)


@pytest.mark.parametrize("name", ["@prime0/ajjv", "magentic-utils"])
def test_an_every_version_advisory_outside_the_lane_is_still_dropped(feed: Path, name: str) -> None:
    network = Network(advisories={"npm": [_advisory("GHSA-aaaa-bbbb-0102", "npm", name, ">= 0")]},
                      refuse=("https://registry.npmjs.org", "https://api.osv.dev"))
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert decision.outcome == "dropped" and "every version (>= 0)" in decision.reason


def test_a_package_a_pin_table_names_is_in_the_lane(feed: Path) -> None:
    network = Network(advisories={"pip": [_advisory("GHSA-aaaa-bbbb-0103", "pip", "gpt-researcher", "= 9.9.9")]})
    [decision] = script.refresh_bundled(feed, opener=network, now=NOW).decisions
    assert (decision.outcome, decision.reason) == (
        "kept", "agent lane: a package the pin tables name; the advisory lists = 9.9.9")


def _lane_flood(count: int) -> Network:
    advisories = []
    for i in range(count):
        advisory = _advisory(f"GHSA-lane-{i:04d}-aaaa", "npm", f"aak-mcp-flood-{i}", "= 1.0.0")
        advisory["published_at"] = _iso(PUBLISHED - timedelta(minutes=count - i))   # 0 is the oldest
        advisories.append(advisory)
    return Network(advisories={"npm": advisories}, refuse=("https://registry.npmjs.org",))


def test_past_the_lane_cap_the_newest_are_held_and_checked_at_is_not_set(feed: Path) -> None:
    outcome = script.refresh_bundled(feed, opener=_lane_flood(51), now=NOW)
    assert [d.outcome for d in outcome.decisions].count("kept") == 50
    [held] = [d for d in outcome.decisions if d.outcome == "held"]
    assert held.name == "aak-mcp-flood-50"
    assert outcome.written and not outcome.checked
    data = json.loads(feed.read_text())
    assert "checked_at" not in data and len(outcome.added) == 50


def test_main_prints_the_review_line_when_the_cap_is_reached(feed: Path, monkeypatch: pytest.MonkeyPatch,
                                                            capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _lane_flood(52))
    assert script.main(["--feed", str(feed)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "REVIEW  lane cap reached, 2 not added" in lines
    assert lines[-1].startswith("52 packages: 50 kept, 0 could not be checked;")
