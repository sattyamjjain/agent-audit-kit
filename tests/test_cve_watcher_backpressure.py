"""The watcher's cap, and the property that makes a cap safe.

Between 2026-08-26 and 2026-09-01 this workflow filed 27 release-gating issues on
a 6-hour cron with no upper bound — eight of them one product's advisory batch in
a single run. Because the release gate blocked on every open `cve-response`
issue, an opener with no back-pressure meant the repository could not ship at
all. That is a bug in the automation, not a backlog.

The pre-filter is deliberately untouched: all 27 were genuine MCP CVEs, so
tightening `is_relevant` would have dropped true positives to fix a rate problem.

`test_held_cves_are_not_recorded_as_filed` is the one that matters. The cap is
only safe because held CVEs stay unrecorded and get found again; if they were
marked filed, back-pressure would silently be data loss.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "cve_watcher.py"


def _load():
    spec = importlib.util.spec_from_file_location("cve_watcher", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cve_watcher"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


def _vuln(cve_id: str, cvss: float, desc: str = "An MCP server tool flaw.") -> dict:
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-09-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": desc}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": cvss, "baseSeverity": "HIGH"}}
                ]
            },
        }
    }


@pytest.fixture
def empty_repo(tmp_path: Path):
    (tmp_path / "CHANGELOG.cves.md").write_text("# ledger\n", encoding="utf-8")
    return tmp_path


def _collect(tmp_path: Path, vulns: list[dict], monkeypatch, backlog: int = 0):
    monkeypatch.setattr(mod, "open_untriaged_count", lambda *_a, **_k: backlog)
    calls = {"n": 0}

    def fetcher(_keyword: str) -> list[dict]:
        calls["n"] += 1
        return vulns if calls["n"] == 1 else []

    return mod.collect_new_cves(
        changelog_path=tmp_path / "CHANGELOG.cves.md",
        state_path=tmp_path / "state.json",
        github_token="t",
        owner_repo="o/r",
        fetcher=fetcher,
    )


def test_cap_limits_one_batch(empty_repo: Path, monkeypatch) -> None:
    """Eight advisories for one product must not become one day's backlog."""
    vulns = [_vuln(f"CVE-2026-9000{i}", 5.0 + i) for i in range(8)]
    results, _ = _collect(empty_repo, vulns, monkeypatch)
    assert len(results) == mod.MAX_NEW_PER_RUN == 5


def test_cap_keeps_the_most_severe(empty_repo: Path, monkeypatch) -> None:
    vulns = [_vuln(f"CVE-2026-9000{i}", float(i)) for i in range(8)]
    results, _ = _collect(empty_repo, vulns, monkeypatch)
    kept = {e["id"] for e in results}
    assert kept == {f"CVE-2026-9000{i}" for i in range(3, 8)}


def test_held_cves_are_not_recorded_as_filed(empty_repo: Path, monkeypatch) -> None:
    """The property the whole cap rests on.

    `filed_cves` suppresses a CVE on every later run. If a held-back CVE landed
    in it, the cap would not be back-pressure — it would be deletion.
    """
    vulns = [_vuln(f"CVE-2026-9000{i}", float(i)) for i in range(8)]
    results, state = _collect(empty_repo, vulns, monkeypatch)
    filed = set(state.get("filed_cves", []))
    assert filed == {e["id"] for e in results}
    held = {f"CVE-2026-9000{i}" for i in range(3)}
    assert not (filed & held), "a held CVE was marked filed and would never re-appear"


def test_deep_queue_files_nothing(empty_repo: Path, monkeypatch) -> None:
    vulns = [_vuln("CVE-2026-90001", 9.9)]
    results, state = _collect(empty_repo, vulns, monkeypatch, backlog=mod.MAX_OPEN_UNTRIAGED)
    assert results == []
    assert not state.get("filed_cves"), "nothing filed means nothing recorded"


def test_a_drained_queue_files_normally(empty_repo: Path, monkeypatch) -> None:
    vulns = [_vuln("CVE-2026-90001", 9.9)]
    results, _ = _collect(empty_repo, vulns, monkeypatch, backlog=0)
    assert [e["id"] for e in results] == ["CVE-2026-90001"]


def test_backpressure_counts_only_untriaged() -> None:
    """Deferred issues have been read and scheduled, and the release gate ignores
    them; throttling against them would stall filing for a queue that is not
    actually blocking anything."""
    assert mod.DEFERRED_LABEL == "cve-deferred"


def test_unreachable_api_does_not_suppress_filing() -> None:
    """Back-pressure must never be the reason a disclosure goes unfiled."""
    assert mod.open_untriaged_count("o/r", None) == 0
    assert mod.open_untriaged_count(None, "t") == 0


def test_window_is_wide_enough_to_survive_the_cap() -> None:
    """A held CVE has to still be inside the NVD query window when the queue
    drains, or the cap becomes silent data loss."""
    import inspect

    default = inspect.signature(mod._fetch).parameters["window_hours"].default
    assert default >= 24 * 7, "window must outlast a multi-day backlog"


def test_the_prefilter_was_left_alone() -> None:
    """All 27 real issues were genuine MCP CVEs. The fix is a limit, not a
    narrower definition of relevance."""
    assert mod.is_relevant("An MCP server exposes a tool over HTTP.")
    assert mod.is_relevant("Model Context Protocol server path traversal.")
    assert not mod.is_relevant("A wordpress plugin escalation with no agent surface.")


# ---------------------------------------------------------------------------
# The gate must not be disableable by labelling alone
# ---------------------------------------------------------------------------
#
# `cve-deferred` exempts an issue from the release gate. docs/RELEASING.md §5:
#
#     The rule for using it honestly: label `cve-deferred` only when the issue
#     has a disposition comment naming what is queued and why. A label without
#     that comment turns the gate off rather than satisfying it.
#
# That was prose, and prose does not fail a build. Labelling thirteen issues and
# writing nothing would have re-opened exactly the hole the gate was rewritten to
# close, and every check in the repository would still have been green.
#
# These two tests read the live tracker. When it cannot be read they SKIP with a
# reason rather than passing quietly: an unchecked tracker must not look like a
# clean one. That is the same rule check_registry_parity.py follows for an
# unreachable registry, and for the same reason.

_MAINTAINER = {"OWNER", "MEMBER", "COLLABORATOR"}


def _label(issue: dict) -> str:
    return f"#{issue.get('number')} {issue.get('title', '')}".strip()


def without_maintainer_comment(issues: list[dict]) -> list[str]:
    """Deferred issues nobody with write access has written on."""
    return [
        _label(i) for i in issues
        if not any(
            (c.get("authorAssociation") or "").upper() in _MAINTAINER
            for c in (i.get("comments") or [])
        )
    ]


def without_disposition_comment(issues: list[dict]) -> list[str]:
    """Deferred issues with no `## Disposition` comment on them."""
    return [
        _label(i) for i in issues
        if not any(
            (c.get("body") or "").lstrip().startswith("## Disposition")
            for c in (i.get("comments") or [])
        )
    ]


def _deferred_issues() -> list[dict]:
    """Open `cve-deferred` issues with their comments, or skip if unreadable."""
    import json
    import shutil
    import subprocess

    if shutil.which("gh") is None:
        pytest.skip("gh CLI not available — the tracker was NOT checked")
    out = subprocess.run(
        [
            "gh", "issue", "list", "--repo", "sattyamjjain/agent-audit-kit",
            "--label", "cve-deferred", "--state", "open", "--limit", "100",
            "--json", "number,title,comments",
        ],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        pytest.skip(
            "could not read the tracker "
            f"({out.stderr.strip()[:120]}) — it was NOT checked, this is not a pass"
        )
    try:
        return json.loads(out.stdout)
    except ValueError:
        pytest.skip("tracker response was not JSON — it was NOT checked")


def test_every_deferred_issue_has_a_maintainer_comment() -> None:
    """A `cve-deferred` label on an issue nobody wrote on is the gate switched off.

    The watcher opens these issues as github-actions[bot]. A maintainer comment is
    the minimum evidence that a human looked before the label was applied.
    """
    issues = _deferred_issues()
    if not issues:
        return  # nothing deferred is a legitimate state
    naked = without_maintainer_comment(issues)
    assert not naked, (
        "cve-deferred applied with no maintainer comment, which exempts these "
        "from the release gate without anyone having dispositioned them:\n  "
        + "\n  ".join(naked)
    )


def test_every_deferred_issue_has_a_disposition_comment() -> None:
    """The stricter half of §5: the comment has to be a disposition.

    A maintainer replying "ack" satisfies the letter of the rule above and none of
    its intent. The disposition heading is the repo's existing convention, used by
    every triage since 2026-08-25.
    """
    issues = _deferred_issues()
    if not issues:
        return
    undispositioned = without_disposition_comment(issues)
    assert not undispositioned, (
        "cve-deferred applied without a `## Disposition:` comment — "
        "docs/RELEASING.md §5 calls this turning the gate off rather than "
        "satisfying it:\n  " + "\n  ".join(undispositioned)
    )


def test_the_gate_check_bites_on_synthetic_data() -> None:
    """Covers the predicates when the tracker cannot be read.

    The two tests above skip without network, and a check that only runs where
    the network is available protects nothing on the machine where somebody is
    actually applying the label. These assertions hold everywhere.
    """
    bot_only = {
        "number": 1, "title": "CVE-response: CVE-0000-1",
        "comments": [{"authorAssociation": "NONE", "body": "opened by the watcher"}],
    }
    acked = {
        "number": 2, "title": "CVE-response: CVE-0000-2",
        "comments": [{"authorAssociation": "OWNER", "body": "ack, will look"}],
    }
    dispositioned = {
        "number": 3, "title": "CVE-response: CVE-0000-3",
        "comments": [{"authorAssociation": "OWNER", "body": "## Disposition: DEFERRED\n\nTarget: 2026-09-09."}],
    }

    # A label with only the bot's own text on it is the gate switched off.
    assert without_maintainer_comment([bot_only]) == ["#1 CVE-response: CVE-0000-1"]
    assert without_maintainer_comment([acked, dispositioned]) == []

    # "ack" clears the maintainer bar and fails the disposition bar, which is the
    # whole reason the second check exists.
    assert without_disposition_comment([acked]) == ["#2 CVE-response: CVE-0000-2"]
    assert without_disposition_comment([dispositioned]) == []
