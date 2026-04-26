"""Engine-level ignore_paths filter (not just the secret_exposure scanner)."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan


def test_ignore_paths_filters_mcp_config_findings(tmp_path: Path) -> None:
    """Findings from a directory listed in ignore_paths must be dropped
    even when the scanner that produced them does not consume the
    `ignore_paths` kwarg directly."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / ".mcp.json").write_text(
        '{"mcpServers": {"evil": {"url": "https://attacker.example/api"}}}',
        encoding="utf-8",
    )
    # Without ignore_paths: AAK-MCP-001 fires.
    res_no_ignore = run_scan(tmp_path, ignore_paths=None)
    assert any(
        f.rule_id == "AAK-MCP-001" and "fixtures" in f.file_path
        for f in res_no_ignore.findings
    ), "expected AAK-MCP-001 from fixtures/.mcp.json without ignore_paths"

    # With ignore_paths=['fixtures']: same finding suppressed.
    res_ignored = run_scan(tmp_path, ignore_paths=["fixtures"])
    assert not any(
        f.rule_id == "AAK-MCP-001" and "fixtures" in f.file_path
        for f in res_ignored.findings
    )


def test_ignore_paths_supports_subpath_match(tmp_path: Path) -> None:
    """ignore_paths='examples/vulnerable' must also drop
    examples/vulnerable/foo/bar."""
    nested = tmp_path / "examples" / "vulnerable" / "deep"
    nested.mkdir(parents=True)
    (nested / ".mcp.json").write_text(
        '{"mcpServers": {"evil": {"url": "https://attacker.example/api"}}}',
        encoding="utf-8",
    )
    res = run_scan(tmp_path, ignore_paths=["examples/vulnerable"])
    assert not any(
        f.rule_id == "AAK-MCP-001" and "examples/vulnerable" in f.file_path
        for f in res.findings
    )


def test_ignore_paths_does_not_drop_findings_outside_prefix(tmp_path: Path) -> None:
    """Edge case: ignore_paths='tests' must not drop a finding under
    tests-look-alike (e.g. testsuite_results/)."""
    twin = tmp_path / "testsuite_results"
    twin.mkdir()
    (twin / ".mcp.json").write_text(
        '{"mcpServers": {"evil": {"url": "https://attacker.example/api"}}}',
        encoding="utf-8",
    )
    res = run_scan(tmp_path, ignore_paths=["tests"])
    assert any(
        f.rule_id == "AAK-MCP-001" and "testsuite_results" in f.file_path
        for f in res.findings
    ), "ignore_paths='tests' must not match 'testsuite_results' as a prefix"


def test_ignore_paths_handles_exact_file_match(tmp_path: Path) -> None:
    """ignore_paths='CLAUDE.md' must drop findings whose file_path is
    exactly 'CLAUDE.md'."""
    (tmp_path / "CLAUDE.md").write_text(
        '```bash\n/scan\n```\n',
        encoding="utf-8",
    )
    res = run_scan(tmp_path, ignore_paths=["CLAUDE.md"])
    assert not any(
        f.file_path == "CLAUDE.md" for f in res.findings
    )


def test_ignore_paths_strips_trailing_slash(tmp_path: Path) -> None:
    """ignore_paths='fixtures/' and 'fixtures' must behave identically."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / ".mcp.json").write_text(
        '{"mcpServers": {"evil": {"url": "https://attacker.example/api"}}}',
        encoding="utf-8",
    )
    res_with_slash = run_scan(tmp_path, ignore_paths=["fixtures/"])
    res_no_slash = run_scan(tmp_path, ignore_paths=["fixtures"])
    assert (
        len([f for f in res_with_slash.findings if f.rule_id == "AAK-MCP-001"])
        == len([f for f in res_no_slash.findings if f.rule_id == "AAK-MCP-001"])
    )
