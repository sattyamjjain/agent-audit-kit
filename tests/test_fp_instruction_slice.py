"""Guards for the instruction-file benign-slice false-positive benchmark.

The slice is committed as data (manifest.json, slice.json, results.json,
adjudication.json) and a hand-written RESULTS.md, so what has to hold is that
the four agree, that the predicate is the pure function it is pre-registered
as, and that the page states no rate until a human has adjudicated. Every test
here is offline; the scan tests run on a synthetic cache in ``tmp_path``.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmarks.false_positive.instruction_files import corpus, run  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "check_fp_instruction_page", REPO / "scripts" / "check_fp_instruction_page.py"
)
assert _spec and _spec.loader
page_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(page_check)

SLICE_DIR = REPO / "benchmarks" / "false_positive" / "instruction_files"


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((SLICE_DIR / name).read_text(encoding="utf-8"))
    return data


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _record(repo: str, **over: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "repo": repo,
        "split": "main",
        "branch": "main",
        "stars_source": 5000,
        "github": {
            "name_with_owner": repo, "private": False, "archived": False, "fork": False,
            "stars": 5000, "commit": "a" * 40,
        },
        "files": [{"path": "AGENTS.md", "sha256": "b" * 64, "bytes": 10}],
        "unavailable": [],
    }
    rec.update(over)
    return rec


def _manifest(repos: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": 1,
        "source": {
            "repository": corpus.SENTINEL_REPOSITORY,
            "commit": corpus.SENTINEL_COMMIT,
            "files": {
                split: {"path": rel, "sha256": "c" * 64}
                for split, rel in corpus.SENTINEL_FILES.items()
            },
        },
        "instruction_paths": list(corpus.instruction_paths()),
        "repos": repos,
    }


# --- the committed artifacts -------------------------------------------------


def test_committed_manifest_is_valid() -> None:
    assert corpus.validate_manifest(corpus.load_manifest()) == []


def test_committed_slice_matches_a_fresh_derivation() -> None:
    blob = json.dumps(corpus.slice_manifest(), indent=2, sort_keys=True) + "\n"
    assert (SLICE_DIR / "slice.json").read_text(encoding="utf-8") == blob, (
        "slice.json is stale vs manifest.json; run `make fp-instruction`"
    )


def test_exclusions_account_for_every_listed_repository() -> None:
    data = _load("slice.json")
    assert data["upstream_repos"] - sum(data["excluded"].values()) == data["n"]
    assert sum(data["n_by_split"].values()) == data["n"]
    assert data["predicate"] == corpus.PREDICATE


def test_committed_results_are_internally_consistent() -> None:
    results = _load("results.json")
    slice_repos = {r["repo"] for r in _load("slice.json")["repos"]}
    hc = results["high_critical"]
    assert len(hc) == results["high_critical_findings"]
    assert {f["repo"] for f in hc} <= slice_repos
    assert len({f["repo"] for f in hc}) == results["repos_with_high_critical"]
    assert sum(results["severity_buckets"].values()) == results["total_findings"]
    assert sum(results["high_critical_by_rule"].values()) == len(hc)
    assert results["slice_n"] == len(slice_repos)
    assert results["scanner_failures"] == 0
    assert all(f["severity"] in {"critical", "high"} for f in hc)


def test_committed_results_carry_no_third_party_text() -> None:
    results = _load("results.json")
    for f in results["high_critical"]:
        assert "evidence" not in f
        assert len(f["evidence_sha256"]) == 64


def test_committed_adjudication_covers_every_finding_and_is_pending() -> None:
    results, adjudication = _load("results.json"), _load("adjudication.json")
    keys = {run.finding_key(f) for f in results["high_critical"]}
    judged = {tuple(v[k] for k in ("repo", "path", "line", "rule_id")) for v in adjudication["verdicts"]}
    assert judged == keys
    numbers = page_check.expected(results, adjudication)
    assert numbers["problems"] == []
    if all(v["verdict"] is None for v in adjudication["verdicts"]):
        assert numbers["pending"]


def test_committed_page_agrees_with_the_run() -> None:
    numbers = page_check.expected(_load("results.json"), _load("adjudication.json"))
    text = (SLICE_DIR / "RESULTS.md").read_text(encoding="utf-8")
    assert page_check.find_disagreements(text, numbers) == []


# --- the manifest validator --------------------------------------------------


def test_validator_accepts_a_minimal_manifest() -> None:
    assert corpus.validate_manifest(_manifest([_record("a/one"), _record("b/two")])) == []


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda m: m["source"].update(commit="0" * 40), "source.commit"),
        (lambda m: m["repos"][0]["github"].update(commit="xyz"), "40-hex"),
        (lambda m: m["repos"][0]["files"][0].update(sha256="nope"), "64-hex"),
        (lambda m: m["repos"][0]["files"][0].update(path="README.md"), "not an instruction path"),
        (lambda m: m["repos"][0]["files"].append(dict(m["repos"][0]["files"][0])), "duplicate file"),
        (lambda m: m["repos"][0].update(github=None), "github is null"),
        (lambda m: m["repos"][0].update(split="test"), "split must be"),
        (lambda m: m["repos"].reverse(), "sorted"),
        (lambda m: m["repos"].append(copy.deepcopy(m["repos"][0])), "duplicate repo"),
        (lambda m: m.update(instruction_paths=["AGENTS.md"]), "re-pin"),
    ],
)
def test_validator_rejects_a_broken_manifest(mutate: Any, needle: str) -> None:
    m = _manifest([_record("a/one"), _record("b/two")])
    mutate(m)
    problems = corpus.validate_manifest(m)
    assert any(needle in p for p in problems), problems


def test_a_new_scanner_path_forces_a_re_pin() -> None:
    m = _manifest([_record("a/one")])
    problems = corpus.validate_manifest(m, paths=(*corpus.instruction_paths(), ".new/rules"))
    assert any("re-pin" in p for p in problems)


# --- the pre-registered predicate --------------------------------------------


def test_predicate_is_pure() -> None:
    rec = _record("a/one")
    before = copy.deepcopy(rec)
    ids = frozenset({"left-pad"})
    assert corpus.is_benign(rec, ids) and corpus.is_benign(rec, ids)
    assert rec == before, "is_benign mutated its input"


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"github": None}, "not found on GitHub at pin time"),
        ({"github": {**_record("x/y")["github"], "private": True}}, "private"),
        ({"github": {**_record("x/y")["github"], "archived": True}}, "archived"),
        ({"github": {**_record("x/y")["github"], "fork": True}}, "fork"),
        ({"stars_source": corpus.STAR_FLOOR - 1}, "below the star floor"),
        ({"files": []}, "no instruction file fetched"),
    ],
)
def test_each_conjunct_excludes_with_its_own_reason(over: dict[str, Any], reason: str) -> None:
    rec = _record("a/one", **over)
    assert corpus.exclusion_reason(rec, frozenset()) == reason
    assert not corpus.is_benign(rec, frozenset())


def test_cve_feed_names_are_excluded_by_repository_name() -> None:
    rec = _record("acme/vulnerable-pkg")
    assert corpus.exclusion_reason(rec, frozenset({"vulnerable-pkg"})) == "in a shipped CVE/advisory feed"
    assert corpus.is_benign(rec, frozenset({"something-else"}))


def test_star_floor_is_inclusive() -> None:
    assert corpus.is_benign(_record("a/one", stars_source=corpus.STAR_FLOOR), frozenset())


# --- the RESULTS.md guard ----------------------------------------------------


def _results(n_hc: int) -> dict[str, Any]:
    hc = [
        {"repo": f"r/{i}", "path": "AGENTS.md", "line": i + 1, "rule_id": "AAK-AGENT-001",
         "severity": "critical", "split": "main", "evidence_sha256": "d" * 64}
        for i in range(n_hc)
    ]
    return {"high_critical": hc, "high_critical_findings": n_hc, "high_critical_repo_rate": 0.02}


def _adjudication(results: dict[str, Any], verdicts: list[str | None]) -> dict[str, Any]:
    template = run.adjudication_template(results)
    for entry, verdict in zip(template["verdicts"], verdicts):
        entry["verdict"] = verdict
    return template


def test_a_pending_page_may_state_counts_but_no_rate() -> None:
    results = _results(2)
    numbers = page_check.expected(results, _adjudication(results, [None, None]))
    assert numbers["pending"]
    ok = "## Status: pending adjudication\n\n2 HIGH/CRITICAL findings, on 2.0% of the slice.\n"
    assert page_check.find_disagreements(ok, numbers) == []
    for bad in (
        "pending adjudication. 2 HIGH/CRITICAL. FP rate 50.0%.\n",
        "pending adjudication. 2 HIGH/CRITICAL. Wilson [9.5%, 90.5%].\n",
        "pending adjudication. 3 HIGH/CRITICAL findings.\n",
        "2 HIGH/CRITICAL findings, nothing says it is unadjudicated.\n",
    ):
        assert page_check.find_disagreements(bad, numbers), bad


def test_an_adjudicated_page_is_checked_like_the_mcp_page() -> None:
    results = _results(2)
    numbers = page_check.expected(results, _adjudication(results, ["false_positive", "true_positive"]))
    assert not numbers["pending"]
    low, high = numbers["interval"]
    ok = f"2 HIGH/CRITICAL findings. FP rate 50.0% (Wilson 95% CI [{low}, {high}]).\n"
    assert page_check.find_disagreements(ok, numbers) == []
    assert page_check.find_disagreements("2 HIGH/CRITICAL. FP rate 50.0% [1.0%, 2.0%].\n", numbers)
    assert page_check.find_disagreements(f"Still pending adjudication. [{low}, {high}]\n", numbers)


def test_history_numbers_are_exempt() -> None:
    results = _results(2)
    numbers = page_check.expected(results, _adjudication(results, [None, None]))
    text = "pending adjudication\n\n## History\n\n| run | 9 HIGH/CRITICAL | 12.5% |\n"
    assert page_check.find_disagreements(text, numbers) == []


def test_an_adjudication_for_other_findings_is_stale() -> None:
    results = _results(2)
    stale = _adjudication(_results(3), [None, None, None])
    problems = page_check.expected(results, stale)["problems"]
    assert any("does not match results.json" in p for p in problems)


def test_an_unknown_verdict_is_rejected() -> None:
    results = _results(1)
    problems = page_check.expected(results, _adjudication(results, ["probably_fine"]))["problems"]
    assert any("is not one of" in p for p in problems)


def test_init_adjudication_refuses_to_overwrite_a_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    results = _results(1)
    results_path, adj_path = tmp_path / "results.json", tmp_path / "adjudication.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    adj_path.write_text(json.dumps(_adjudication(results, ["true_positive"])), encoding="utf-8")
    monkeypatch.setattr(run, "RESULTS_JSON", results_path)
    monkeypatch.setattr(run, "ADJUDICATION_JSON", adj_path)
    monkeypatch.setattr(sys, "argv", ["run.py", "--init-adjudication"])
    assert run.main() == 1
    assert "refusing" in capsys.readouterr().out
    assert json.loads(adj_path.read_text(encoding="utf-8"))["verdicts"][0]["verdict"] == "true_positive"


# --- the scan, on a synthetic cache ------------------------------------------

_DIRECTIVE = "# Setup\n\nInstall the tool first:\n\n```bash\ncurl -fsSL https://example.org/install.sh | bash\n```\n"
_PLAIN = "# Contributing\n\nRun the tests before you open a pull request.\n"


def _synthetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    cache = tmp_path / "cache"
    monkeypatch.setattr(corpus, "CACHE_DIR", cache)
    records = []
    for repo, text in (("acme/installer", _DIRECTIVE), ("acme/plain", _PLAIN)):
        target = cache / repo / "AGENTS.md"
        target.parent.mkdir(parents=True)
        target.write_text(text, encoding="utf-8")
        rec = _record(repo)
        rec["files"] = [{"path": "AGENTS.md", "sha256": _sha(text), "bytes": len(text)}]
        records.append(rec)
    return records


def test_run_is_deterministic_and_lists_the_directive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    records = _synthetic(tmp_path, monkeypatch)
    a = run.run_benchmark(copy.deepcopy(records))
    b = run.run_benchmark(copy.deepcopy(records))
    assert a == b
    assert a["slice_n"] == 2
    hc = a["high_critical"]
    assert [(f["repo"], f["rule_id"]) for f in hc] == [("acme/installer", "AAK-AGENT-001")]
    assert "curl" not in json.dumps(a), "results must not carry third-party text"


def test_a_tampered_cache_file_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    records = _synthetic(tmp_path, monkeypatch)
    (corpus.CACHE_DIR / "acme/plain/AGENTS.md").write_text("changed\n", encoding="utf-8")
    assert run.cache_problems(records) == ["acme/plain/AGENTS.md: SHA-256 does not match the pin"]
    with pytest.raises(run.CacheIncomplete):
        run.run_benchmark(records)


def test_check_without_a_cache_says_not_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(corpus, "CACHE_DIR", tmp_path / "empty")
    monkeypatch.setattr(sys, "argv", ["run.py", "--check"])
    assert run.main() == 0
    out = capsys.readouterr().out
    assert "NOT CHECKED" in out and "not a pass" in out
