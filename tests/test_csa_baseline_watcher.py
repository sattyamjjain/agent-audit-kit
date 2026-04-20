"""Tests for scripts/watch_csa_mcp_baseline.py (Task H)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_script():
    path = REPO_ROOT / "scripts" / "watch_csa_mcp_baseline.py"
    spec = importlib.util.spec_from_file_location("csa_watcher", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["csa_watcher"] = module
    spec.loader.exec_module(module)
    return module


def test_detects_version_in_html() -> None:
    module = _load_script()
    html = '<p>Announcing the MCP Security Baseline v0.1 RC1 release notes...</p>'
    with patch.object(module, "_fetch", return_value=html):
        versions = module._detect_versions(["https://example.com/announcement"])
    assert "0.1" in versions


def test_no_match_when_phrase_absent() -> None:
    module = _load_script()
    html = '<p>Totally unrelated page about AI Controls Matrix v1.0.</p>'
    with patch.object(module, "_fetch", return_value=html):
        assert module._detect_versions(["https://example.com/x"]) == set()


def test_dry_run_writes_no_state(tmp_path: Path) -> None:
    module = _load_script()
    state = tmp_path / "state.json"
    with patch.object(module, "_fetch", return_value="MCP Security Baseline v0.2"):
        rc = module.main([
            "--sources", "https://example.com",
            "--state", str(state),
            "--dry-run",
        ])
    assert rc == 0
    assert not state.is_file()


def test_seen_versions_are_skipped_on_subsequent_runs(tmp_path: Path, monkeypatch) -> None:
    module = _load_script()
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"seen_versions": ["0.1"]}))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with patch.object(module, "_fetch", return_value="MCP Security Baseline v0.1"):
        rc = module.main(["--sources", "https://example.com", "--state", str(state)])
    assert rc == 0
    # State untouched: no new versions.
    assert json.loads(state.read_text())["seen_versions"] == ["0.1"]


def test_new_version_records_state_without_token(tmp_path: Path, monkeypatch, capsys) -> None:
    module = _load_script()
    state = tmp_path / "state.json"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with patch.object(module, "_fetch", return_value="MCP Security Baseline v0.3.1"):
        rc = module.main(["--sources", "https://example.com", "--state", str(state)])
    assert rc == 0
    payload = json.loads(state.read_text())
    assert "0.3.1" in payload["seen_versions"]
    out = capsys.readouterr().out
    assert "would file issue" in out  # no token → logs intent only


def test_no_sources_reachable_returns_zero(tmp_path: Path) -> None:
    module = _load_script()
    with patch.object(module, "_fetch", return_value=None):
        rc = module.main(["--sources", "https://example.com", "--state", str(tmp_path / "s.json")])
    assert rc == 0
