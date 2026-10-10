"""Tests for agent_audit_kit.diff module."""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_audit_kit import engine
from agent_audit_kit.cli import cli
from agent_audit_kit.diff import _changed_paths, filter_by_diff, get_changed_files
from agent_audit_kit.models import (
    SCANNER_FAIL_RULE_ID,
    Category,
    Finding,
    ScanResult,
    Severity,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_finding(file_path: str, rule_id: str = "AAK-TEST-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        category=Category.MCP_CONFIG,
        file_path=file_path,
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A committed repository with a scanned subdirectory and a sibling."""
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (root / "other").mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "config", "core.hooksPath", os.devnull)
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (root / "sub" / "a.json").write_text("{}\n", encoding="utf-8")
    (root / "sub" / "b.json").write_text("{}\n", encoding="utf-8")
    (root / "other" / "c.json").write_text("{}\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


class TestGetChangedFiles:
    def test_returns_empty_set_for_non_git_dir(self, tmp_path: Path) -> None:
        result = get_changed_files(tmp_path)
        assert result == set()

    def test_returns_files_from_git_diff(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "file1.json\0file2.py\0"
            result = get_changed_files(tmp_path)

        assert result == {"file1.json", "file2.py"}

    def test_returns_empty_on_nonzero_return_code(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 128
            mock_run.return_value.stdout = ""
            result = get_changed_files(tmp_path)

        assert result == set()

    def test_handles_timeout(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=30)
            result = get_changed_files(tmp_path)

        assert result == set()

    def test_passes_base_ref(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            get_changed_files(tmp_path, base_ref="main")

        diff_args = mock_run.call_args_list[0][0][0]
        assert diff_args[:2] == ["git", "diff"]
        assert "main" in diff_args
        assert "--relative" in diff_args

    def test_nul_delimited_names_are_kept_verbatim(self, tmp_path: Path) -> None:
        """No stripping: with -z the bytes between NULs are the name."""
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "my dir/a b.json\0café.json\0"
            result = get_changed_files(tmp_path)

        assert result == {"my dir/a b.json", "café.json"}


class TestChangedPathsInARealRepo:
    """The paths have to match the ones findings carry, so test them against git."""

    def test_paths_are_relative_to_the_scanned_subdirectory(self, repo: Path) -> None:
        (repo / "sub" / "a.json").write_text('{"x": 1}\n', encoding="utf-8")
        assert get_changed_files(repo / "sub", "HEAD") == {"a.json"}

    def test_repository_root_paths_are_unchanged(self, repo: Path) -> None:
        (repo / "sub" / "a.json").write_text('{"x": 1}\n', encoding="utf-8")
        assert get_changed_files(repo, "HEAD") == {"sub/a.json"}

    def test_changes_outside_the_scanned_directory_are_left_out(self, repo: Path) -> None:
        (repo / "other" / "c.json").write_text('{"x": 1}\n', encoding="utf-8")
        # Git answered, and nothing under sub/ changed: an empty set, not "unknown".
        assert _changed_paths(repo / "sub", "HEAD") == set()

    def test_untracked_file_counts_as_changed(self, repo: Path) -> None:
        (repo / "sub" / "new.json").write_text("{}\n", encoding="utf-8")
        assert get_changed_files(repo / "sub", "HEAD") == {"new.json"}

    def test_gitignored_file_does_not_count(self, repo: Path) -> None:
        (repo / "sub" / "debug.log").write_text("x\n", encoding="utf-8")
        assert get_changed_files(repo / "sub", "HEAD") == set()

    def test_a_name_git_would_quote_comes_back_verbatim(self, repo: Path) -> None:
        name = "café config.json"
        (repo / "sub" / name).write_text("{}\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add")
        (repo / "sub" / name).write_text('{"x": 1}\n', encoding="utf-8")
        assert get_changed_files(repo / "sub", "HEAD") == {name}

    def test_unknown_ref_means_git_could_not_answer(self, repo: Path) -> None:
        assert _changed_paths(repo, "no-such-ref") is None
        assert get_changed_files(repo, "no-such-ref") == set()

    def test_a_ref_that_looks_like_an_option_is_not_run_as_one(
        self, repo: Path, tmp_path: Path
    ) -> None:
        leak = tmp_path / "leak.txt"
        assert _changed_paths(repo, f"--output={leak}") is None
        assert not leak.exists()


class TestFilterByDiff:
    def test_filters_findings_to_changed_files(self, tmp_path: Path) -> None:
        scan_result = ScanResult(
            findings=[
                _make_finding(".mcp.json"),
                _make_finding("other.json"),
                _make_finding("untouched.py"),
            ],
            files_scanned=3,
            rules_evaluated=10,
        )
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = {".mcp.json", "other.json"}
            filtered = filter_by_diff(scan_result, tmp_path)

        assert len(filtered.findings) == 2
        assert all(f.file_path in {".mcp.json", "other.json"} for f in filtered.findings)

    def test_returns_original_when_git_cannot_answer(self, tmp_path: Path) -> None:
        scan_result = ScanResult(
            findings=[_make_finding(".mcp.json")],
            files_scanned=1,
            rules_evaluated=5,
        )
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = None
            filtered = filter_by_diff(scan_result, tmp_path)

        assert filtered is scan_result

    def test_a_real_non_git_directory_is_returned_unfiltered(self, tmp_path: Path) -> None:
        scan_result = ScanResult(findings=[_make_finding(".mcp.json")])
        assert filter_by_diff(scan_result, tmp_path, "HEAD") is scan_result

    def test_nothing_changed_drops_every_file_finding(self, tmp_path: Path) -> None:
        """A monorepo PR that touched only a sibling package: nothing to report here."""
        failure = _make_finding("<scanner>", rule_id=SCANNER_FAIL_RULE_ID)
        scan_result = ScanResult(findings=[_make_finding(".mcp.json"), failure])
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = set()
            filtered = filter_by_diff(scan_result, tmp_path)

        assert filtered.findings == [failure]

    def test_scanner_failure_survives_the_filter(self, tmp_path: Path) -> None:
        failure = _make_finding("<scanner>", rule_id=SCANNER_FAIL_RULE_ID)
        scan_result = ScanResult(findings=[_make_finding("untouched.py"), failure])
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = {".mcp.json"}
            filtered = filter_by_diff(scan_result, tmp_path)

        assert filtered.findings == [failure]
        assert filtered.scanner_failures == [failure]

    def test_other_internal_and_pseudo_path_findings_survive(self, tmp_path: Path) -> None:
        internal = _make_finding("whatever.json", rule_id="AAK-INTERNAL-OTHER")
        pseudo = _make_finding("<session>")
        scan_result = ScanResult(findings=[internal, pseudo, _make_finding("untouched.py")])
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = {".mcp.json"}
            filtered = filter_by_diff(scan_result, tmp_path)

        assert filtered.findings == [internal, pseudo]

    def test_every_other_field_is_preserved(self, tmp_path: Path) -> None:
        scan_result = ScanResult(
            findings=[_make_finding(".mcp.json"), _make_finding("untouched.py")],
            files_scanned=7,
            rules_evaluated=11,
            scan_duration_ms=12.5,
            score=80,
            grade="B",
        )
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = {".mcp.json"}
            filtered = filter_by_diff(scan_result, tmp_path)

        for fld in dataclasses.fields(ScanResult):
            if fld.name != "findings":
                assert getattr(filtered, fld.name) == getattr(scan_result, fld.name), fld.name

    def test_empty_findings_returns_empty(self, tmp_path: Path) -> None:
        scan_result = ScanResult(findings=[], files_scanned=0, rules_evaluated=5)
        with patch("agent_audit_kit.diff._changed_paths") as mock_changed:
            mock_changed.return_value = {"file.py"}
            filtered = filter_by_diff(scan_result, tmp_path)

        assert len(filtered.findings) == 0


# ---------------------------------------------------------------------------
# End to end through `aak scan --diff`
# ---------------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture()
def _fresh_registry() -> Iterator[None]:
    """The registry caches scan functions, so a patched scanner needs a rebuild."""
    engine.reset_registry()
    yield
    engine.reset_registry()


def _vulnerable_subproject(repo: Path) -> Path:
    """repo/sub with a changed .mcp.json and an unchanged .cursor/mcp.json."""
    sub = repo / "sub"
    (sub / ".cursor").mkdir()
    (sub / ".mcp.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")
    shutil.copy(FIXTURES / "vulnerable_mcp.json", sub / ".cursor" / "mcp.json")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "configs")
    shutil.copy(FIXTURES / "vulnerable_mcp.json", sub / ".mcp.json")
    return sub


def test_scanning_a_subdirectory_keeps_findings_in_changed_files(
    repo: Path, tmp_path: Path
) -> None:
    sub = _vulnerable_subproject(repo)
    out = tmp_path / "out.json"
    runner.invoke(
        cli, ["scan", str(sub), "--diff", "HEAD", "--format", "json", "-o", str(out)]
    )
    reported = {f["filePath"] for f in json.loads(out.read_text())["findings"]}
    assert ".mcp.json" in reported, "the changed config's findings were dropped"
    assert ".cursor/mcp.json" not in reported, "an unchanged config was reported"


def test_a_scanner_crash_under_diff_still_ends_incomplete(
    repo: Path, monkeypatch: pytest.MonkeyPatch, _fresh_registry: None
) -> None:
    from agent_audit_kit.scanners import mcp_config

    def _boom(*args: object, **kwargs: object) -> tuple[list[Finding], set[str]]:
        raise RuntimeError("boom")

    monkeypatch.setattr(mcp_config, "scan", _boom)
    engine.reset_registry()
    sub = _vulnerable_subproject(repo)

    res = runner.invoke(cli, ["scan", str(sub), "--diff", "HEAD"])

    assert res.exit_code == 1, res.output
    assert "INCOMPLETE" in res.output
