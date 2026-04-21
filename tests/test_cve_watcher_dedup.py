"""Dedup regression test for scripts/cve_watcher.py.

Guards against the 2026-04-20/21 regression where the same CVE was
filed on every 6-hour cron (issues #47/#48/#50/#52/#55 — five copies of
CVE-2026-6599 in 48 hours). Three dedup layers: CHANGELOG, state file,
open issues. Any one must suppress.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module():
    path = REPO_ROOT / "scripts" / "cve_watcher.py"
    spec = importlib.util.spec_from_file_location("cve_watcher_mod", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cve_watcher_mod"] = module
    spec.loader.exec_module(module)
    return module


def _vuln(cve_id: str) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-04-21T00:00:00.000",
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}
                ]
            },
            "descriptions": [{"lang": "en", "value": f"Synthetic record for {cve_id}"}],
        }
    }


def test_state_file_suppresses_repeat(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"filed_cves": ["CVE-2026-6599"]}), encoding="utf-8")
    changelog = tmp_path / "CHANGELOG.cves.md"  # absent
    results, _ = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token=None,
        owner_repo=None,
        fetcher=lambda _kw: [_vuln("CVE-2026-6599")],
    )
    assert results == []


def test_changelog_still_suppresses(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "state.json"
    changelog = tmp_path / "CHANGELOG.cves.md"
    changelog.write_text("... CVE-2025-66335 → AAK-DORIS-001 ...\n", encoding="utf-8")
    results, _ = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token=None,
        owner_repo=None,
        fetcher=lambda _kw: [_vuln("CVE-2025-66335")],
    )
    assert results == []


def test_three_calls_produce_one_file_event(tmp_path: Path) -> None:
    """Replay the observed incident: same CVE arrives on three cron runs.

    After the first run writes state, runs two and three must dedup even
    though the changelog has not yet been updated and no open issue has
    been opened (simulating the race where the issue-file API call fails).
    """

    module = _load_module()
    state = tmp_path / "state.json"
    changelog = tmp_path / "CHANGELOG.cves.md"

    fetcher = lambda _kw: [_vuln("CVE-2026-99999")]

    run1, state_after_1 = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token=None,
        owner_repo=None,
        fetcher=fetcher,
    )
    assert [e["id"] for e in run1] == ["CVE-2026-99999"]
    module._save_state(state, state_after_1)

    run2, _ = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token=None,
        owner_repo=None,
        fetcher=fetcher,
    )
    assert run2 == []

    run3, _ = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token=None,
        owner_repo=None,
        fetcher=fetcher,
    )
    assert run3 == []


def test_open_issue_title_suppresses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "_open_issue_cves",
        lambda *a, **kw: {"CVE-2026-39861"},
    )
    state = tmp_path / "state.json"
    changelog = tmp_path / "CHANGELOG.cves.md"
    results, _ = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token="fake-token",
        owner_repo="acme/repo",
        fetcher=lambda _kw: [_vuln("CVE-2026-39861")],
    )
    assert results == []


def test_new_cve_passes_all_layers(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "state.json"
    changelog = tmp_path / "CHANGELOG.cves.md"
    results, updated = module.collect_new_cves(
        changelog_path=changelog,
        state_path=state,
        github_token=None,
        owner_repo=None,
        fetcher=lambda _kw: [_vuln("CVE-2026-77777")],
    )
    assert [e["id"] for e in results] == ["CVE-2026-77777"]
    assert "CVE-2026-77777" in updated["filed_cves"]
