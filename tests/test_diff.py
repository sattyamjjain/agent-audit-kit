"""Tests for agent_audit_kit.diff module."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agent_audit_kit.diff import filter_by_diff, get_changed_files
from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)


def _make_finding(file_path: str) -> Finding:
    return Finding(
        rule_id="AAK-TEST-001",
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        category=Category.MCP_CONFIG,
        file_path=file_path,
    )


class TestGetChangedFiles:
    def test_returns_empty_set_for_non_git_dir(self, tmp_path: Path) -> None:
        result = get_changed_files(tmp_path)
        assert result == set()

    def test_returns_files_from_git_diff(self, tmp_path: Path) -> None:
        mock_output = "file1.json\nfile2.py\n"
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = mock_output
            result = get_changed_files(tmp_path)

        assert result == {"file1.json", "file2.py"}

    def test_returns_empty_on_nonzero_return_code(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 128
            mock_run.return_value.stdout = ""
            result = get_changed_files(tmp_path)

        assert result == set()

    def test_handles_timeout(self, tmp_path: Path) -> None:
        import subprocess

        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=30)
            result = get_changed_files(tmp_path)

        assert result == set()

    def test_passes_base_ref(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            get_changed_files(tmp_path, base_ref="main")

        call_args = mock_run.call_args[0][0]
        assert "main" in call_args

    def test_strips_whitespace_from_filenames(self, tmp_path: Path) -> None:
        with patch("agent_audit_kit.diff.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "  file.py  \n\n  other.json \n"
            result = get_changed_files(tmp_path)

        assert result == {"file.py", "other.json"}


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
        with patch("agent_audit_kit.diff.get_changed_files") as mock_changed:
            mock_changed.return_value = {".mcp.json", "other.json"}
            filtered = filter_by_diff(scan_result, tmp_path)

        assert len(filtered.findings) == 2
        assert all(f.file_path in {".mcp.json", "other.json"} for f in filtered.findings)

    def test_returns_original_when_no_changed_files(self, tmp_path: Path) -> None:
        scan_result = ScanResult(
            findings=[_make_finding(".mcp.json")],
            files_scanned=1,
            rules_evaluated=5,
        )
        with patch("agent_audit_kit.diff.get_changed_files") as mock_changed:
            mock_changed.return_value = set()
            filtered = filter_by_diff(scan_result, tmp_path)

        assert filtered is scan_result

    def test_empty_findings_returns_empty(self, tmp_path: Path) -> None:
        scan_result = ScanResult(findings=[], files_scanned=0, rules_evaluated=5)
        with patch("agent_audit_kit.diff.get_changed_files") as mock_changed:
            mock_changed.return_value = {"file.py"}
            filtered = filter_by_diff(scan_result, tmp_path)

        assert len(filtered.findings) == 0
