"""The CVE watcher's second source: OSV, by package, for every name the pin tables name.

NVD's keyword feed misses a flaw in a pinned package whose text never says MCP,
and an OSV `MAL-` record never reaches NVD at all. These tests pin which names the
watcher asks OSV about (read from the scanner sources with `ast`, every registry
stated), how an OSV record becomes the same record shape the workflow files, the
window, dedup by id and alias, and that NVD-only callers (every older test) never
reach OSV. Nothing here touches the network.
"""

from __future__ import annotations

import ast
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "cve-watcher.yml"
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def _load():
    spec = importlib.util.spec_from_file_location("cve_watcher_osv_mod", REPO / "scripts" / "cve_watcher.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = _load()


# ---- which packages ------------------------------------------------------------


def test_the_pin_tables_names_are_read_with_their_registries() -> None:
    packages = set(w.pinned_packages())
    for want in [
        ("PyPI", "litellm"),
        ("npm", "@google-cloud/cloud-run-mcp"),
        ("npm", "cloud-run-mcp"),
        ("npm", "@toolbox-sdk/server"),
        ("PyPI", "langchain-core"),          # a DependencyPin
        ("npm", "@modelcontextprotocol/sdk"),
        ("Maven", "io.modelcontextprotocol:kotlin-sdk-core"),  # a _JvmPin
        ("PyPI", "serena-agent"),             # a supply_chain floor
        ("npm", "@anthropic-ai/claude-code"),  # a pattern-matched floor
    ]:
        assert want in packages, want
    assert all(eco in ("PyPI", "npm", "Maven") for eco, _ in packages)
    assert not any("/" in name and name.count(".") > 0 and name.startswith(("ghcr.io", "docker.io"))
                   for _, name in packages), "an image name reached OSV"


def test_every_legacy_floor_names_its_registry() -> None:
    """supply_chain's `_affected_pin` floors carry no registry; each must be in
    `_LEGACY_REGISTRY`, or the watcher would ask both registries about it."""
    tree = ast.parse((REPO / "agent_audit_kit" / "scanners" / "supply_chain.py").read_text())
    constants = {
        s.targets[0].id: ast.literal_eval(s.value) for s in tree.body
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name)
        and isinstance(s.value, ast.Tuple) and all(isinstance(e, ast.Constant) for e in s.value.elts)
    }
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_affected_pin" and len(node.args) > 2:
            arg = node.args[2]
            value = constants.get(arg.id) if isinstance(arg, ast.Name) else ast.literal_eval(arg)
            names.update(value or ())
    assert names, "no _affected_pin floors found"
    assert names <= set(w._LEGACY_REGISTRY), sorted(names - set(w._LEGACY_REGISTRY))


# ---- from OSV records to watcher records ------------------------------------------


def _osv(records: dict[str, dict], pages: dict[tuple[str, str], list[list[dict]]] | None = None):
    """A stub of OSV's querybatch and vuln endpoints."""
    pages = {k: list(v) for k, v in (pages or {}).items()}
    calls: list[str] = []

    def http(url: str, payload: dict | None = None) -> dict:
        calls.append(url)
        if url == w.OSV_QUERYBATCH:
            results = []
            assert payload is not None
            for query in payload["queries"]:
                key = (query["package"]["ecosystem"], query["package"]["name"])
                page = pages.get(key, [[]])
                vulns = page.pop(0) if page else []
                result: dict = {"vulns": vulns}
                if page:
                    result["next_page_token"] = f"next-{key[1]}"
                results.append(result)
            return {"results": results}
        osv_id = url.rsplit("/", 1)[-1]
        return records[osv_id]

    return http, calls


def _record(osv_id: str, published: str, aliases: tuple[str, ...] = (), **extra: object) -> dict:
    return {"id": osv_id, "published": published, "modified": published, "aliases": list(aliases),
            "summary": f"summary of {osv_id}", "details": "details", **extra}


PKG: tuple[str, str] = ("PyPI", "litellm")


def test_records_inside_the_window_are_filed_under_their_cve() -> None:
    recent, old = "2026-10-27T15:32:36Z", "2026-03-24T11:15:14Z"
    records = {
        "GHSA-c2c2-f3f3-g4g4": _record("GHSA-c2c2-f3f3-g4g4", recent, ("CVE-2026-90001",)),
        "MAL-2026-9": _record("MAL-2026-9", recent),
        "MAL-2026-2144": _record("MAL-2026-2144", old, modified="2026-10-21T22:01:01.881791175Z"),
    }
    vulns = [{"id": k, "modified": r.get("modified", r["published"])} for k, r in records.items()]
    http, _ = _osv(records, {PKG: [vulns]})
    scored = []
    out = w.osv_records(set(), packages=[PKG], http=http, now=NOW,
                        scorer=lambda cve: scored.append(cve) or {"score": 9.1, "version": "3.1",
                                                                   "source": "nvd@nist.gov", "type": "Primary"},
                        ghsa_scorer=lambda _g: pytest.fail("a CVE alias is scored by NVD"))
    by_id = {e["id"]: e for e in out}
    assert set(by_id) == {"CVE-2026-90001", "MAL-2026-9"}  # the March record is outside the window
    assert scored == ["CVE-2026-90001"]
    cve = by_id["CVE-2026-90001"]
    assert (cve["cvss"], cve["severity"], cve["aliases"]) == (9.1, "CRITICAL", ["GHSA-c2c2-f3f3-g4g4"])
    assert cve["source"].startswith("OSV GHSA-c2c2-f3f3-g4g4 (PyPI `litellm`")
    assert cve["url"] == "https://osv.dev/vulnerability/GHSA-c2c2-f3f3-g4g4"
    mal = by_id["MAL-2026-9"]
    assert (mal["cvss"], mal["severity"], mal["url"]) == (None, None, "https://osv.dev/vulnerability/MAL-2026-9")


def test_a_ghsa_without_a_cve_is_scored_by_github() -> None:
    records = {"GHSA-f6f6-g7g7-h8h8": _record("GHSA-f6f6-g7g7-h8h8", "2026-10-27T15:31:56Z")}
    http, _ = _osv(records, {PKG: [[{"id": "GHSA-f6f6-g7g7-h8h8", "modified": "2026-10-27T15:31:56Z"}]]})
    out = w.osv_records(set(), packages=[PKG], http=http, now=NOW, scorer=lambda _c: None,
                        ghsa_scorer=lambda g: {"score": 7.5, "version": "3.1", "source": "GitHub", "type": "Secondary"})
    assert [(e["id"], e["cvss"], e["severity"]) for e in out] == [("GHSA-f6f6-g7g7-h8h8", 7.5, "HIGH")]


class _Response:
    def __init__(self, body: dict) -> None:
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


# GitHub's own shapes, as /advisories returned them on 2026-10-28: a metric it does
# not have is score 0 with no vector.
_ABSENT = {"score": 0, "vector_string": None}
_V31 = {"score": 3.1, "vector_string": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N"}
_V30 = {"score": 7.5, "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
_V40 = {"score": 8.7, "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}


@pytest.mark.parametrize(
    ("severities", "want"),
    [
        ({"cvss_v3": _ABSENT, "cvss_v4": _V40}, (8.7, "4.0")),
        ({"cvss_v3": _V31, "cvss_v4": _ABSENT}, (3.1, "3.1")),
        ({"cvss_v3": _V30, "cvss_v4": _V40}, (7.5, "3.0")),
        ({"cvss_v3": _ABSENT, "cvss_v4": _ABSENT}, None),
    ],
)
def test_github_scores_are_read_by_their_vector(
    monkeypatch: pytest.MonkeyPatch, severities: dict, want: tuple[float, str] | None
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "placeholder")
    asked: list[str] = []

    def urlopen(req: object, timeout: float | None = None) -> _Response:
        asked.append(getattr(req, "full_url", ""))
        return _Response({"cvss_severities": severities})

    monkeypatch.setattr(w.urllib.request, "urlopen", urlopen)
    got = w._ghsa_score("GHSA-x94g-w73q-hpcw")
    assert asked == ["https://api.github.com/advisories/GHSA-x94g-w73q-hpcw"]
    assert (None if got is None else (got["score"], got["version"])) == want


def test_without_a_token_github_is_not_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(w.urllib.request, "urlopen", lambda *_a, **_k: pytest.fail("GitHub was asked"))
    assert w._ghsa_score("GHSA-x94g-w73q-hpcw") is None


def test_tracked_withdrawn_and_paged_records() -> None:
    recent = "2026-10-27T00:00:00Z"
    records = {
        "GHSA-2222-3333-4444": _record("GHSA-2222-3333-4444", recent, ("CVE-2026-90002",)),  # alias tracked
        "GHSA-4444-5555-6666": _record("GHSA-4444-5555-6666", recent, withdrawn="2026-10-27T01:00:00Z"),
        "MAL-2026-10": _record("MAL-2026-10", recent),  # on the second page
    }
    pages = {PKG: [[{"id": "GHSA-2222-3333-4444", "modified": recent},
                    {"id": "GHSA-4444-5555-6666", "modified": recent}],
                   [{"id": "MAL-2026-10", "modified": recent}]]}
    http, calls = _osv(records, pages)
    out = w.osv_records({"CVE-2026-90002"}, packages=[PKG], http=http, now=NOW,
                        scorer=lambda _c: None, ghsa_scorer=lambda _g: None)
    assert [e["id"] for e in out] == ["MAL-2026-10"]
    assert calls.count(w.OSV_QUERYBATCH) == 2


def test_an_osv_failure_leaves_nvd_alone(capsys: pytest.CaptureFixture[str]) -> None:
    def broken(*_a: object, **_k: object) -> dict:
        raise OSError("unreachable (test)")

    assert w.osv_records(set(), packages=[PKG], http=broken, now=NOW) == []
    assert "NVD only this run" in capsys.readouterr().err


# ---- one list, one dedup ----------------------------------------------------------------


def test_osv_records_join_nvd_records_under_one_dedup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "CHANGELOG.cves.md").write_text("| CVE-2026-90005 | ledgered |\n")
    monkeypatch.setattr(w, "_all_issue_cves", lambda *_a: {"GHSA-9999-8888-7777"})
    monkeypatch.setattr(w, "open_untriaged_count", lambda *_a: 0)
    nvd = {"cve": {"id": "CVE-2026-90001", "published": "2026-10-27T00:00:00",
                   "descriptions": [{"lang": "en", "value": "an MCP server flaw"}], "metrics": {}}}
    seen_suppressed: list[set[str]] = []

    def osv_source(suppressed: set[str]) -> list[dict]:
        seen_suppressed.append(set(suppressed))
        return [
            {"id": "CVE-2026-90001", "aliases": ["GHSA-h5h5-j6j6-m7m7"]},   # NVD already has it
            {"id": "CVE-2026-90005", "aliases": []},                        # in the ledger
            {"id": "GHSA-7777-6666-5555", "aliases": ["GHSA-9999-8888-7777"]},  # in an issue
            {"id": "MAL-2026-11", "aliases": [], "source": "OSV MAL-2026-11"},
        ]

    results, state = w.collect_new_cves(
        changelog_path=tmp_path / "CHANGELOG.cves.md", state_path=tmp_path / "state.json",
        github_token="t", owner_repo="o/r", fetcher=lambda _kw: [nvd], osv_source=osv_source,
    )
    assert [r["id"] for r in results] == ["CVE-2026-90001", "MAL-2026-11"]
    assert {"CVE-2026-90005", "GHSA-9999-8888-7777", "CVE-2026-90001"} <= seen_suppressed[0]
    assert {"CVE-2026-90001", "MAL-2026-11"} <= set(state["filed_cves"])


def test_without_an_osv_source_only_nvd_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(w, "_all_issue_cves", lambda *_a: set())
    monkeypatch.setattr(w, "open_untriaged_count", lambda *_a: 0)
    monkeypatch.setattr(w, "osv_records", lambda *_a, **_k: pytest.fail("OSV was read"))
    results, _ = w.collect_new_cves(changelog_path=tmp_path / "c.md", state_path=tmp_path / "s.json",
                                    fetcher=lambda _kw: [])
    assert results == []


def test_main_reads_both_sources() -> None:
    tree = ast.parse((REPO / "scripts" / "cve_watcher.py").read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    call = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "collect_new_cves")
    assert any(k.arg == "osv_source" and getattr(k.value, "id", "") == "osv_records" for k in call.keywords)


def test_the_workflow_says_what_it_reads_and_names_the_source() -> None:
    text = WORKFLOW.read_text()
    header = text.split("\non:", 1)[0]
    assert "Queries NVD's keyword feed" in header and "OSV" in header and "MAL-" in header
    assert "**Source:** ${cve.source ?? 'NVD keyword feed'}" in text
    assert "`**OSV:** ${cve.url}`" in text
