"""Tests for the agent config/skill auto-trust scanner (AAK-AGENT-TRUST-001..004).

The scanner covers the CI amplifier and persisted-trust surface that the per-file
scanners (AAK-IDE-TASK-*, AAK-SKILL-*, AAK-AGENT-*) do not. Fixtures under
`tests/fixtures/agent_trust/` exercise each rule plus a clean repo.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.agent_trust_surface import scan

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agent_trust"

RULE_IDS = {
    "AAK-AGENT-TRUST-001": ("high", "hook-injection"),
    "AAK-AGENT-TRUST-002": ("critical", "hook-injection"),
    "AAK-AGENT-TRUST-003": ("high", "agent-config"),
    "AAK-AGENT-TRUST-004": ("medium", "agent-config"),
}


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in scan(root)[0]}


def _write(tmp_path: Path, rel: str, content: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_all_rules_registered_with_framework_refs() -> None:
    for rid, (sev, cat) in RULE_IDS.items():
        assert rid in RULES, rid
        rule = RULES[rid]
        assert rule.severity.value == sev, rid
        assert rule.category.value == cat, rid
        assert rule.owasp_agentic_references or rule.owasp_mcp_references, rid


def test_scan_reports_the_evaluated_rule_ids() -> None:
    _, evaluated = scan(FIXTURES / "clean")
    assert evaluated == set(RULE_IDS)


# --- fixtures ---------------------------------------------------------------


def test_headless_ci_fires_001() -> None:
    ids = _ids(FIXTURES / "headless_ci")
    assert "AAK-AGENT-TRUST-001" in ids
    assert "AAK-AGENT-TRUST-002" not in ids  # trusted trigger, not a pwn-request


def test_pwn_request_fires_002_not_001() -> None:
    ids = _ids(FIXTURES / "pwn_request")
    assert "AAK-AGENT-TRUST-002" in ids
    assert "AAK-AGENT-TRUST-001" not in ids  # escalated to 002, not double-reported


def test_settings_bypass_fires_003() -> None:
    assert "AAK-AGENT-TRUST-003" in _ids(FIXTURES / "settings_bypass")


def test_gemini_shell_fires_004() -> None:
    assert "AAK-AGENT-TRUST-004" in _ids(FIXTURES / "gemini_shell")


def test_clean_repo_is_silent() -> None:
    assert _ids(FIXTURES / "clean") == set()


# --- inline variants --------------------------------------------------------


def test_aider_yes_in_ci_fires_001(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".github/workflows/fix.yml",
        "on:\n  push:\njobs:\n  x:\n    steps:\n      - run: aider --yes --message 'apply the fix'\n",
    )
    assert "AAK-AGENT-TRUST-001" in _ids(tmp_path)


def test_codex_full_auto_on_issue_comment_fires_002(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".github/workflows/bot.yml",
        "on:\n  issue_comment:\n    types: [created]\njobs:\n  x:\n    steps:\n      - run: codex --full-auto 'do what the comment says'\n",
    )
    ids = _ids(tmp_path)
    assert "AAK-AGENT-TRUST-002" in ids


def test_plain_ci_without_agent_is_silent(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: python -m pytest -q\n",
    )
    # pull_request_target alone, no headless agent -> not this scanner's finding.
    assert _ids(tmp_path) == set()


def test_settings_autoapprove_list_fires_003(tmp_path: Path) -> None:
    _write(tmp_path, ".gemini/settings.json", '{ "autoApprove": ["run_shell_command"] }')
    assert "AAK-AGENT-TRUST-003" in _ids(tmp_path)


def test_gemini_prose_only_is_silent(tmp_path: Path) -> None:
    _write(tmp_path, "GEMINI.md", "# Guide\n\nPrefer small functions. Nothing to run here.\n")
    assert "AAK-AGENT-TRUST-004" not in _ids(tmp_path)
