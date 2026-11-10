"""Tests for the agent config/skill auto-trust scanner (AAK-AGENT-TRUST-001..004).

The scanner covers the CI amplifier and persisted-trust surface that the per-file
scanners (AAK-IDE-TASK-*, AAK-SKILL-*, AAK-AGENT-*) do not. Fixtures under
`tests/fixtures/agent_trust/` exercise each rule plus a clean repo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_scan_reports_scanned_files_not_rule_ids() -> None:
    """The second tuple element is scanned file paths, not rule ids (#743).

    This test used to assert the opposite. The engine unions that set into
    ``files_scanned``, so returning rule ids made an empty directory report
    files it never opened, and rule coverage is computed separately from the
    active rule set regardless.
    """
    _, scanned = scan(FIXTURES / "clean")
    assert not (scanned & set(RULE_IDS))
    for rel in scanned:
        assert (FIXTURES / "clean" / rel).is_file(), rel


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


_CRAFTED_WORKFLOWS = {
    # Every `claude` on a line read on to the line's end looking for a flag.
    "cli-words": "on: push\njobs:\n  a:\n    steps:\n      - run: " + "claude " * 140_000 + "\n",
    # From every line start in a run of blank lines `^\s*` read to its end.
    "blank-lines": "on: push\n" + "\n" * 990_000 + "x\n",
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_WORKFLOWS))
def test_a_crafted_workflow_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    """About 1 MB, the scanner's workflow cap. Both shapes grew with the square
    of the line or run. The bound is loose for slow CI runners."""
    import time

    _write(tmp_path, ".github/workflows/ci.yml", _CRAFTED_WORKFLOWS[shape])
    started = time.perf_counter()
    _ids(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_headless_evidence_quotes_from_the_first_cli_name(tmp_path: Path) -> None:
    """Only the first `claude` per stretch of a line is tried now; the match is
    still the one that starts there and reads on past a second mention."""
    from agent_audit_kit.scanners.agent_trust_surface import _headless_hit

    hit = _headless_hit('steps:\n  - run: claude "ask claude about the diff" -p\n')
    assert hit is not None and hit.group(0) == 'claude "ask claude about the diff" -p'


# --- AAK-AGENT-TRUST-002: an agent with write access, given another project's commits ------------

_PORT_STEPS = """\
      - run: gh api "repos/${UPSTREAM}/compare/main...next" > TASK.md
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: Read TASK.md and port the change.
"""


def _port_workflow(steps: str = _PORT_STEPS, permissions: str = "contents: write", top: str = "", on: str = "schedule:\n    - cron: '0 8 * * 1'") -> str:
    return (
        f"on:\n  {on}\n{top}jobs:\n  port:\n    runs-on: ubuntu-latest\n"
        f"    permissions:\n      {permissions}\n    steps:\n{steps}"
    )


def _trust_rules(tmp_path: Path, text: str) -> list[str]:
    _write(tmp_path, ".github/workflows/port.yml", text)
    return [f.rule_id for f in scan(tmp_path)[0] if f.rule_id in ("AAK-AGENT-TRUST-001", "AAK-AGENT-TRUST-002")]


def test_third_party_diff_to_a_writing_agent_fires_002(tmp_path: Path) -> None:
    _write(tmp_path, ".github/workflows/port.yml", _port_workflow())
    found = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-AGENT-TRUST-002"]
    assert len(found) == 1
    assert "run-gemini-cli" in found[0].evidence and "contents: write" in found[0].evidence
    assert "repos/${UPSTREAM}/compare" in found[0].evidence
    assert found[0].line_number == 11


def test_it_replaces_001_rather_than_doubling_it(tmp_path: Path) -> None:
    assert _trust_rules(tmp_path, _port_workflow()) == ["AAK-AGENT-TRUST-002"]


@pytest.mark.parametrize("on", [
    "schedule:\n    - cron: '0 8 * * 1'", "workflow_dispatch:", "repository_dispatch:", "workflow_call:", "push:",
])
def test_the_trigger_does_not_decide_it(tmp_path: Path, on: str) -> None:
    assert _trust_rules(tmp_path, _port_workflow(on=on)) == ["AAK-AGENT-TRUST-002"]


@pytest.mark.parametrize("fetch", [
    "git fetch upstream main",
    "git fetch https://github.com/example/upstream.git",
    'git fetch --depth 1 "$UPSTREAM_URL" main',
    "git remote add upstream https://github.com/example/upstream.git",
    'gh api "/repos/${UPSTREAM_REPO}/commits/${SHA}"',
    "gh api repos/example/upstream/compare/a...b",
    "gh api 'repos/${{ inputs.upstream_repo }}/commits'",
    "curl -s https://api.github.com/repos/example/upstream/compare/a...b",
])
def test_the_ways_of_fetching_another_project(tmp_path: Path, fetch: str) -> None:
    steps = f"      - run: {json_quote(fetch)}\n      - uses: anthropics/claude-code-action@v1\n"
    assert _trust_rules(tmp_path, _port_workflow(steps)) == ["AAK-AGENT-TRUST-002"]


def json_quote(text: str) -> str:
    """A YAML scalar that keeps every character of a command."""
    return "'" + text.replace("'", "''") + "'"


@pytest.mark.parametrize("fetch", [
    "git fetch",
    "git fetch origin",
    "git fetch --depth 1 origin main",
    "git fetch --all",
    "gh api repos/${{ github.repository }}/compare/a...b",
    'gh api "repos/$GITHUB_REPOSITORY/commits"',
    "gh api repos/{owner}/{repo}/compare/a...b",
    "gh api repos/example/upstream/issues",
    "curl -s https://example.com/repos/example/upstream/compare/a...b",
])
def test_this_projects_own_commits_do_not_count(tmp_path: Path, fetch: str) -> None:
    steps = f"      - run: {json_quote(fetch)}\n      - uses: anthropics/claude-code-action@v1\n"
    assert _trust_rules(tmp_path, _port_workflow(steps)) == ["AAK-AGENT-TRUST-001"]


def test_a_variable_set_from_this_repository_is_this_project(tmp_path: Path) -> None:
    steps = (
        '      - run: gh api "repos/${REPO}/compare/a...b"\n'
        "        env:\n          REPO: ${{ github.repository }}\n"
        "      - uses: anthropics/claude-code-action@v1\n"
    )
    assert _trust_rules(tmp_path, _port_workflow(steps)) == ["AAK-AGENT-TRUST-001"]


def test_an_env_on_the_workflow_is_read_too(tmp_path: Path) -> None:
    steps = '      - run: gh api "repos/${REPO}/compare/a...b"\n      - uses: anthropics/claude-code-action@v1\n'
    top = "env:\n  REPO: ${{ github.repository }}\n"
    assert _trust_rules(tmp_path, _port_workflow(steps, top=top)) == ["AAK-AGENT-TRUST-001"]


@pytest.mark.parametrize("permissions", ["contents: read", "issues: write", "pull-requests: read"])
def test_no_write_scope_is_001_only(tmp_path: Path, permissions: str) -> None:
    assert _trust_rules(tmp_path, _port_workflow(permissions=permissions)) == ["AAK-AGENT-TRUST-001"]


def test_empty_job_permissions_are_001_only(tmp_path: Path) -> None:
    text = f"on:\n  schedule:\n    - cron: '0 8 * * 1'\npermissions:\n  contents: write\njobs:\n  port:\n    permissions: {{}}\n    steps:\n{_PORT_STEPS}"
    assert _trust_rules(tmp_path, text) == ["AAK-AGENT-TRUST-001"]


def test_top_level_write_scope_counts_when_the_job_states_none(tmp_path: Path) -> None:
    text = f"on:\n  schedule:\n    - cron: '0 8 * * 1'\npermissions:\n  pull-requests: write\njobs:\n  port:\n    steps:\n{_PORT_STEPS}"
    assert _trust_rules(tmp_path, text) == ["AAK-AGENT-TRUST-002"]


def test_write_all_counts(tmp_path: Path) -> None:
    text = f"on:\n  schedule:\n    - cron: '0 8 * * 1'\npermissions: write-all\njobs:\n  port:\n    steps:\n{_PORT_STEPS}"
    assert _trust_rules(tmp_path, text) == ["AAK-AGENT-TRUST-002"]


@pytest.mark.parametrize("env, expected", [
    ("GH_TOKEN: ${{ secrets.COPILOT_PAT }}", "AAK-AGENT-TRUST-002"),
    ("GH_TOKEN: ${{ secrets.PORTING_TOKEN }}", "AAK-AGENT-TRUST-002"),
    ("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}", "AAK-AGENT-TRUST-001"),
    ("GEMINI_TOKEN: ${{ secrets.GEMINI_TOKEN }}", "AAK-AGENT-TRUST-001"),
    ("API_KEY: ${{ secrets.GEMINI_API_KEY }}", "AAK-AGENT-TRUST-001"),
])
def test_a_personal_token_counts_as_write_access(tmp_path: Path, env: str, expected: str) -> None:
    steps = _PORT_STEPS + f"        env:\n          {env}\n"
    assert _trust_rules(tmp_path, _port_workflow(steps, permissions="contents: read")) == [expected]


def test_a_token_in_the_job_env_counts(tmp_path: Path) -> None:
    text = (
        "on:\n  schedule:\n    - cron: '0 8 * * 1'\njobs:\n  port:\n    permissions:\n      contents: read\n"
        f"    env:\n      GH_TOKEN: ${{{{ secrets.COPILOT_PAT }}}}\n    steps:\n{_PORT_STEPS}"
    )
    assert _trust_rules(tmp_path, text) == ["AAK-AGENT-TRUST-002"]


def test_a_token_in_another_step_does_not_count(tmp_path: Path) -> None:
    steps = (
        '      - run: gh api "repos/${UPSTREAM}/compare/a...b"\n'
        "        env:\n          GH_TOKEN: ${{ secrets.COPILOT_PAT }}\n"
        "      - uses: anthropics/claude-code-action@v1\n"
    )
    assert _trust_rules(tmp_path, _port_workflow(steps, permissions="contents: read")) == ["AAK-AGENT-TRUST-001"]


@pytest.mark.parametrize("command", ["gh agent-task create -F TASK.md", "copilot -p 'port it'", "copilot --allow-all-tools"])
def test_the_copilot_agent_counts(tmp_path: Path, command: str) -> None:
    steps = f'      - run: gh api "repos/${{UPSTREAM}}/compare/a...b"\n      - run: {command}\n'
    assert _trust_rules(tmp_path, _port_workflow(steps)) == ["AAK-AGENT-TRUST-002"]


def test_a_blocking_egress_policy_stands_it_down(tmp_path: Path) -> None:
    steps = (
        "      - uses: step-security/harden-runner@v2\n        with:\n          egress-policy: block\n" + _PORT_STEPS
    )
    assert _trust_rules(tmp_path, _port_workflow(steps)) == ["AAK-AGENT-TRUST-001"]


def test_an_audit_egress_policy_does_not(tmp_path: Path) -> None:
    steps = (
        "      - uses: step-security/harden-runner@v2\n        with:\n          egress-policy: audit\n" + _PORT_STEPS
    )
    assert _trust_rules(tmp_path, _port_workflow(steps)) == ["AAK-AGENT-TRUST-002"]


def test_the_fetch_may_sit_in_another_job(tmp_path: Path) -> None:
    text = (
        "on:\n  schedule:\n    - cron: '0 8 * * 1'\njobs:\n  scan:\n    permissions: {}\n    steps:\n"
        '      - run: gh api "repos/${UPSTREAM}/commits"\n'
        "  port:\n    needs: scan\n    permissions:\n      contents: write\n    steps:\n"
        "      - uses: google-github-actions/run-gemini-cli@v0\n"
    )
    assert _trust_rules(tmp_path, text) == ["AAK-AGENT-TRUST-002"]


def test_the_remediation_shape_is_quiet(tmp_path: Path) -> None:
    """Agent with no permissions on a schedule; a `workflow_run` writer that runs no agent."""
    _write(tmp_path, ".github/workflows/agent.yml", _port_workflow(permissions="{}").replace("permissions:\n      {}", "permissions: {}"))
    _write(
        tmp_path,
        ".github/workflows/apply.yml",
        "on:\n  workflow_run:\n    workflows: [agent]\n    types: [completed]\njobs:\n  apply:\n"
        "    permissions:\n      contents: write\n    steps:\n      - run: git apply result.patch\n",
    )
    assert "AAK-AGENT-TRUST-002" not in _ids(tmp_path)


def test_no_agent_is_quiet(tmp_path: Path) -> None:
    steps = '      - run: gh api "repos/${UPSTREAM}/compare/a...b"\n      - run: make port\n'
    assert _trust_rules(tmp_path, _port_workflow(steps)) == []


@pytest.mark.parametrize("text", [
    "on: [\n",
    "- not\n- a mapping\n",
    "jobs: []\n# git fetch upstream\n",
    "jobs:\n  a: 1\n  b:\n    steps: 2\n  c:\n    steps: [1, 2]\n# git fetch upstream\n",
])
def test_a_malformed_workflow_does_not_crash_it(tmp_path: Path, text: str) -> None:
    _write(tmp_path, ".github/workflows/port.yml", text)
    assert "AAK-AGENT-TRUST-002" not in _ids(tmp_path)
