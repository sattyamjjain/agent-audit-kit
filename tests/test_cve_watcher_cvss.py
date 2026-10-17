"""Which CVSS score the watcher files when NVD has several, or not the one it read.

`scripts/cve_watcher.py` read `cvssMetricV31` and nothing else, so a record whose
only score was a CNA's CVSS 4.0 metric was filed "(unknown CVSS n/a)" with
`sev/unknown`: #917, #918 and #919 (CVE-2026-105806, -105799 and -106119) and #1026
(CVE-2026-96620, which GitHub scores 9.2), each retitled by hand at disposition.

The metric blocks below were recorded from the NVD API on 2026-10-16 between 21:58Z
and 22:01Z and trimmed to the fields the watcher reads: source, type, and
cvssData's version, vector, base score and severity, plus the metric-level severity
CVSS 2.0 carries; an SSVC block keeps only its source, role and version. Every
shape the precedence has to settle is a real record. The few cases built from them
say how.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


watcher = _load("cve_watcher_cvss_mod", "cve_watcher.py")
gate = _load("check_cve_ageing_cvss_mod", "check_cve_ageing.py")

_SSVC = {"source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
         "ssvcData": {"role": "CISA Coordinator", "version": "2.0.3"}}

RECORDED: dict[str, dict[str, Any]] = {
    # 3.1 only, from the CNA, beside CISA's SSVC block. Deferred.
    "CVE-2026-111311": {
        "cvssMetricV31": [{"source": "security@wordfence.com", "type": "Secondary",
                           "cvssData": {"version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 8.8, "baseSeverity": "HIGH"}}],
        "ssvcV203": [_SSVC],
    },
    # 4.0 only, from the CNA. Received. Filed as "(unknown CVSS n/a)" on 2026-10-16.
    "CVE-2026-96620": {
        "cvssMetricV40": [{"source": "security-advisories@github.com", "type": "Secondary",
                           "cvssData": {"version": "4.0",
                                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                        "baseScore": 9.2, "baseSeverity": "CRITICAL"}}],
    },
    # Both, from one CNA, in different bands: 4.0 says 9.2 CRITICAL, 3.1 says 7.7 HIGH.
    # Awaiting Analysis.
    "CVE-2026-102551": {
        "cvssMetricV40": [{"source": "ff89ba41-3aa1-4d27-914a-91399e9639e5", "type": "Secondary",
                           "cvssData": {"version": "4.0",
                                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                        "baseScore": 9.2, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV31": [{"source": "ff89ba41-3aa1-4d27-914a-91399e9639e5", "type": "Secondary",
                           "cvssData": {"version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
                                        "baseScore": 7.7, "baseSeverity": "HIGH"}}],
    },
    # 4.0, 3.1 and 2.0 from one CNA: 2.1 LOW, 6.3 MEDIUM and 6.5 MEDIUM. Deferred.
    "CVE-2026-109402": {
        "cvssMetricV40": [{"source": "cna@vuldb.com", "type": "Secondary",
                           "cvssData": {"version": "4.0",
                                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                        "baseScore": 2.1, "baseSeverity": "LOW"}}],
        "cvssMetricV31": [{"source": "cna@vuldb.com", "type": "Secondary",
                           "cvssData": {"version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                                        "baseScore": 6.3, "baseSeverity": "MEDIUM"}}],
        "cvssMetricV2": [{"source": "cna@vuldb.com", "type": "Secondary",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                                       "baseScore": 6.5},
                          "baseSeverity": "MEDIUM"}],
        "ssvcV203": [_SSVC],
    },
    # NVD's own 3.1 (Primary) beside GitHub's 4.0 (Secondary). Analyzed.
    "CVE-2025-59536": {
        "cvssMetricV40": [{"source": "security-advisories@github.com", "type": "Secondary",
                           "cvssData": {"version": "4.0",
                                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                        "baseScore": 8.7, "baseSeverity": "HIGH"}}],
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                        "baseScore": 8.8, "baseSeverity": "HIGH"}}],
        "ssvcV203": [_SSVC],
    },
    # NVD's own 3.1 at 8.8 HIGH beside huntr's 3.0 at 6.5 MEDIUM. Analyzed.
    "CVE-2024-3571": {
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 8.8, "baseSeverity": "HIGH"}}],
        "cvssMetricV30": [{"source": "security@huntr.dev", "type": "Secondary",
                           "cvssData": {"version": "3.0",
                                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                        "baseScore": 6.5, "baseSeverity": "MEDIUM"}}],
        "ssvcV203": [_SSVC],
    },
    # NVD's 3.1 and CISA's 3.1 at the same score, and NVD's own 2.0 at 9.3. Analyzed.
    "CVE-2018-11776": {
        "cvssMetricV31": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                          "baseScore": 8.1, "baseSeverity": "HIGH"}},
            {"source": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "type": "Secondary",
             "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                          "baseScore": 8.1, "baseSeverity": "HIGH"}},
        ],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                       "baseScore": 9.3},
                          "baseSeverity": "HIGH"}],
        "ssvcV203": [_SSVC],
    },
    # 3.0 and 2.0, both NVD's. Modified.
    "CVE-2016-0800": {
        "cvssMetricV30": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.0",
                                        "vectorString": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                        "baseScore": 5.9, "baseSeverity": "MEDIUM"}}],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                       "baseScore": 4.3},
                          "baseSeverity": "MEDIUM"}],
    },
    # 2.0 only, NVD's, its severity on the metric rather than in cvssData. Modified.
    "CVE-2005-2088": {
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                       "baseScore": 4.3},
                          "baseSeverity": "MEDIUM"}],
    },
    # No metric at all. Awaiting Analysis.
    "CVE-2026-46471": {},
}


def _vuln(cve_id: str, metrics: dict[str, Any] | None, description: str = "") -> dict[str, Any]:
    cve: dict[str, Any] = {
        "id": cve_id,
        "published": "2026-10-16T20:18:28.293",
        "descriptions": [{"lang": "en", "value": description or f"An MCP server flaw, {cve_id}."}],
    }
    if metrics is not None:
        cve["metrics"] = metrics
    return {"cve": cve}


def _entry(cve_id: str, metrics: dict[str, Any] | None) -> dict[str, Any]:
    return watcher._extract(_vuln(cve_id, metrics))


def _picked(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (entry["cvss"], entry["severity"], entry["cvss_version"],
            entry["cvss_source"], entry["cvss_type"])


@pytest.mark.parametrize(("cve_id", "expected"), [
    # 3.1 only, beside an SSVC block, which carries no score.
    ("CVE-2026-111311", (8.8, "HIGH", "3.1", "security@wordfence.com", "Secondary")),
    # 4.0 only: filed as "(unknown CVSS n/a)" before the fix.
    ("CVE-2026-96620", (9.2, "CRITICAL", "4.0", "security-advisories@github.com", "Secondary")),
    # Both: 4.0 waits for 3.x, so the record keeps the 7.7 HIGH it was always filed at.
    ("CVE-2026-102551", (7.7, "HIGH", "3.1", "ff89ba41-3aa1-4d27-914a-91399e9639e5", "Secondary")),
    # 4.0 (2.1 LOW), 3.1 (6.3 MEDIUM) and 2.0 (6.5): 3.1.
    ("CVE-2026-109402", (6.3, "MEDIUM", "3.1", "cna@vuldb.com", "Secondary")),
    # NVD's Primary 3.1 over GitHub's Secondary 4.0.
    ("CVE-2025-59536", (8.8, "HIGH", "3.1", "nvd@nist.gov", "Primary")),
    # NVD's Primary 3.1 (8.8 HIGH) over huntr's Secondary 3.0 (6.5 MEDIUM).
    ("CVE-2024-3571", (8.8, "HIGH", "3.1", "nvd@nist.gov", "Primary")),
    # NVD's 3.1 over CISA's equal 3.1 and over NVD's own 2.0 at 9.3.
    ("CVE-2018-11776", (8.1, "HIGH", "3.1", "nvd@nist.gov", "Primary")),
    # 3.0 over 2.0.
    ("CVE-2016-0800", (5.9, "MEDIUM", "3.0", "nvd@nist.gov", "Primary")),
    # 2.0 only.
    ("CVE-2005-2088", (4.3, "MEDIUM", "2.0", "nvd@nist.gov", "Primary")),
])
def test_each_recorded_shape_files_the_score_the_precedence_names(
    cve_id: str, expected: tuple[Any, ...]
) -> None:
    assert _picked(_entry(cve_id, RECORDED[cve_id])) == expected


@pytest.mark.parametrize("metrics", [
    RECORDED["CVE-2026-46471"],           # `metrics: {}`, as recorded
    None,                                 # no `metrics` key at all
    {"ssvcV203": [_SSVC]},                # CVE-2026-111311's SSVC block on its own
])
def test_a_record_with_no_cvss_metric_has_no_score(metrics: dict[str, Any] | None) -> None:
    entry = _entry("CVE-2026-46471", metrics)
    assert _picked(entry) == (None, None, None, None, None)


def test_nvds_own_metric_wins_wherever_it_is_listed() -> None:
    """CVE-2018-11776's two 3.1 metrics in the other order, CISA's Secondary first.
    NVD documents no order, and the old reader took whichever came first."""
    metrics = copy.deepcopy(RECORDED["CVE-2018-11776"])
    metrics["cvssMetricV31"].reverse()
    assert _picked(_entry("CVE-2018-11776", metrics))[3:] == ("nvd@nist.gov", "Primary")


def test_source_comes_before_version() -> None:
    """NVD's Primary 3.0 (CVE-2016-0800) beside a CNA's Secondary 3.1 (CVE-2026-111311)
    in one record: NVD's own analysis is used, though 3.1 ranks above 3.0."""
    metrics = {
        "cvssMetricV31": copy.deepcopy(RECORDED["CVE-2026-111311"]["cvssMetricV31"]),
        "cvssMetricV30": copy.deepcopy(RECORDED["CVE-2016-0800"]["cvssMetricV30"]),
    }
    assert _picked(_entry("CVE-2016-0800", metrics)) == (5.9, "MEDIUM", "3.0", "nvd@nist.gov", "Primary")


def test_the_band_comes_from_the_score_not_the_metric() -> None:
    """CVE-2018-11776's 2.0 metric on its own: CVSS 2.0 calls 9.3 HIGH, and the
    ageing gate reads "CVSS 9.3" in a title as critical. The title has to say what the
    gate and the label will read."""
    metrics = {"cvssMetricV2": copy.deepcopy(RECORDED["CVE-2018-11776"]["cvssMetricV2"])}
    entry = _entry("CVE-2018-11776", metrics)
    assert (entry["cvss"], entry["severity"]) == (9.3, "CRITICAL")


@pytest.mark.parametrize("score", [0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0])
def test_the_severity_word_is_the_ageing_gates_band(score: float) -> None:
    metrics = {"cvssMetricV40": [{"source": "cna@example.org", "type": "Secondary",
                                  "cvssData": {"version": "4.0", "baseScore": score}}]}
    assert _entry("CVE-2026-0001", metrics)["severity"] == gate.band_for_score(score).upper()


@pytest.mark.parametrize("bad", [None, "9.8", True, -1.0, 10.5, float("nan")])
def test_an_unusable_score_falls_through_to_the_next_metric(bad: Any) -> None:
    """A Primary metric without a usable base score does not cost the record the
    CNA's score beside it."""
    metrics = {
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.1", "baseScore": bad}}],
        "cvssMetricV40": copy.deepcopy(RECORDED["CVE-2026-96620"]["cvssMetricV40"]),
    }
    assert _picked(_entry("CVE-2026-96620", metrics))[:3] == (9.2, "CRITICAL", "4.0")


def test_a_critical_scored_only_in_4_0_survives_the_cap(tmp_path: Path, monkeypatch) -> None:
    """The cap keeps the most severe. Scored as nothing, CVE-2026-96620 sorted below
    five MEDIUM records and was the one held back."""
    (tmp_path / "CHANGELOG.cves.md").write_text("# ledger\n", encoding="utf-8")
    medium = {"cvssMetricV31": [{"source": "cna@example.org", "type": "Secondary",
                                 "cvssData": {"version": "3.1", "baseScore": 5.0}}]}
    description = (
        "Claude Agent SDK is a Python SDK for Claude Code. Prior to 0.2.121, the resume "
        "option is passed to the Claude CLI as a separate token without validation, so a "
        "dash-leading value is parsed as an independent CLI flag. An attacker can inject the "
        "--mcp-config flag to define a stdio MCP server, causing arbitrary command execution "
        "at CLI startup outside the SDK permission controls. The issue is exploitable when an "
        "application passes untrusted input as the session ID to resume. This issue is fixed "
        "in version 0.2.121."
    )
    vulns = [_vuln(f"CVE-2026-9100{i}", medium) for i in range(5)]
    vulns.append(_vuln("CVE-2026-96620", RECORDED["CVE-2026-96620"], description))
    monkeypatch.setattr(watcher, "open_untriaged_count", lambda *_a, **_k: 0)
    calls = {"n": 0}

    def fetcher(_keyword: str) -> list[dict[str, Any]]:
        calls["n"] += 1
        return vulns if calls["n"] == 1 else []

    results, _ = watcher.collect_new_cves(
        changelog_path=tmp_path / "CHANGELOG.cves.md",
        state_path=tmp_path / "state.json",
        github_token="t",
        owner_repo="o/r",
        fetcher=fetcher,
    )
    assert len(results) == watcher.MAX_NEW_PER_RUN
    assert "CVE-2026-96620" in {e["id"] for e in results}


# ---------------------------------------------------------------------------
# The workflow files what the watcher picked, and labels it as the gate reads it
# ---------------------------------------------------------------------------

_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cve-watcher.yml"

# Runs the issue-filing step's script the way actions/github-script does, as the
# body of an async function, with a stub client that records each issue.
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
    wf = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    for job in wf["jobs"].values():
        for step in job.get("steps") or []:
            if step.get("name") == "File response-tracking issue":
                return step["with"]["script"]
    raise AssertionError("the issue-filing step is gone from cve-watcher.yml")


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node to run the workflow's script")
def test_the_workflow_titles_and_labels_each_recorded_shape(tmp_path: Path) -> None:
    entries = [_entry(cve_id, metrics) for cve_id, metrics in RECORDED.items()]
    (tmp_path / "new_cves.json").write_text(json.dumps(entries), encoding="utf-8")
    (tmp_path / "script.js").write_text(_filing_script(), encoding="utf-8")
    (tmp_path / "runner.cjs").write_text(_RUNNER, encoding="utf-8")
    run = subprocess.run(
        ["node", "runner.cjs", "script.js"],
        cwd=tmp_path, capture_output=True, text=True, timeout=60, check=False,
    )
    assert run.returncode == 0, run.stderr
    issues = {issue["title"].split()[1]: issue for issue in json.loads(run.stdout)}
    assert set(issues) == set(RECORDED)
    for entry in entries:
        issue = issues[entry["id"]]
        band = gate.band_for_issue({"title": issue["title"]})
        # The label the workflow applied is the band the gate will age it in.
        assert issue["labels"] == ["cve-response", gate.sev_label(band)], issue["title"]
        if entry["cvss"] is None:
            assert issue["title"] == f"CVE-response: {entry['id']} (unknown CVSS n/a)"
            assert "**CVSS:** n/a\n" in issue["body"]
            continue
        # The title's number is the score; its word is the band of that number.
        assert issue["title"] == (
            f"CVE-response: {entry['id']} ({band.upper()} CVSS {entry['cvss']:g})"
        )
        assert entry["severity"] == band.upper()
        # The body says which metric the number came from.
        assert (
            f"**CVSS:** {entry['cvss']:g} (v{entry['cvss_version']}, {entry['cvss_type']} "
            f"metric from {entry['cvss_source']})\n"
        ) in issue["body"]
    assert issues["CVE-2026-96620"]["title"] == "CVE-response: CVE-2026-96620 (CRITICAL CVSS 9.2)"
    assert issues["CVE-2026-96620"]["labels"] == ["cve-response", "sev/critical"]
