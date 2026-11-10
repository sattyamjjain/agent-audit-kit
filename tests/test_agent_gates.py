"""AAK-POLICY-OPTIONAL-TRUST-001, AAK-HOOK-FAILOPEN-001 and AAK-AGENT-SUBAGENT-TOOLS-001.

The shape sources are fixture files under `tests/fixtures/agent_gates/`, so the self-scan does not
read them here. The hook scripts are real scripts: the first hook tests run them through a real
interpreter where one is installed, so the rule's verdict and the exit code are checked side by side.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.agent_gates import RULE_HOOK, RULE_OPTIONAL, RULE_SUBAGENT, scan

FIXTURES = Path(__file__).parent / "fixtures" / "agent_gates"
OPTIONAL = FIXTURES / "optional"
HOOKS = FIXTURES / "hooks"


def _rules(root: Path, rule: str) -> list[Any]:
    return [f for f in scan(root)[0] if f.rule_id == rule]


def test_rules_are_registered() -> None:
    assert RULES[RULE_OPTIONAL].severity is Severity.MEDIUM
    assert RULES[RULE_OPTIONAL].category is Category.TRUST_BOUNDARY
    assert RULES[RULE_HOOK].severity is Severity.HIGH
    assert RULES[RULE_HOOK].category is Category.HOOK_INJECTION
    assert RULES[RULE_SUBAGENT].severity is Severity.MEDIUM
    assert RULES[RULE_SUBAGENT].category is Category.AGENT_CONFIG
    for rule in (RULE_OPTIONAL, RULE_HOOK, RULE_SUBAGENT):
        assert RULES[rule].limitations
        assert not RULES[rule].owasp_mcp_references, "not an MCP surface"


def test_the_engine_runs_the_module(tmp_path: Path) -> None:
    shutil.copy(OPTIONAL / "positive_none.py", tmp_path / "guard.py")
    result = run_scan(project_root=tmp_path, rules=[RULE_OPTIONAL], strict_loading=True)
    assert [f.rule_id for f in result.findings] == [RULE_OPTIONAL]


# -- AAK-POLICY-OPTIONAL-TRUST-001 ------------------------------------------------------------


@pytest.mark.parametrize("name, expected", [
    ("positive_none.py", "key_matches_pin is False"),
    ("positive_required_optional.py", "token_valid is False"),
    ("positive_refute.py", "key_revoked is True"),
    ("positive_default_true.py", "verified=True"),
    ("positive_default_false.py", "revoked=False"),
])
def test_a_check_that_passes_on_nothing_fires(tmp_path: Path, name: str, expected: str) -> None:
    shutil.copy(OPTIONAL / name, tmp_path / "guard.py")
    found = _rules(tmp_path, RULE_OPTIONAL)
    assert len(found) == 1
    assert expected in found[0].evidence
    assert found[0].line_number and found[0].line_number > 1


@pytest.mark.parametrize("name", sorted(p.name for p in OPTIONAL.glob("negative_*.py")))
def test_a_check_that_answers_none_does_not_fire(tmp_path: Path, name: str) -> None:
    shutil.copy(OPTIONAL / name, tmp_path / "guard.py")
    assert _rules(tmp_path, RULE_OPTIONAL) == []


@pytest.mark.parametrize("rel", ["tests/guard.py", "fixtures/guard.py", "test_guard.py", "guard_test.py", "conftest.py"])
def test_test_paths_are_skipped(tmp_path: Path, rel: str) -> None:
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(OPTIONAL / "positive_none.py", target)
    assert _rules(tmp_path, RULE_OPTIONAL) == []


def test_a_nested_function_is_read_on_its_own(tmp_path: Path) -> None:
    (tmp_path / "guard.py").write_text(
        "def outer(verified=None):\n"
        "    def inner(verified=None):\n"
        "        if verified is None:\n"
        "            return 'unknown'\n"
        "        return 'known'\n"
        "    if verified is False:\n"
        "        return inner()\n"
        "    return 'admit'\n"
    )
    found = _rules(tmp_path, RULE_OPTIONAL)
    assert [f.line_number for f in found] == [6]


def test_a_test_in_an_and_or_is_read(tmp_path: Path) -> None:
    (tmp_path / "guard.py").write_text(
        "def admit(strict, verified=None):\n"
        "    if strict and verified is False:\n"
        "        raise PermissionError('no')\n"
        "    return 'admit'\n"
    )
    assert len(_rules(tmp_path, RULE_OPTIONAL)) == 1


@pytest.mark.parametrize("annotation", ['"Optional[bool]"', '"typing.Optional[bool]"', '"bool | None"', '"Union[None, bool]"'])
def test_a_quoted_annotation_is_read(tmp_path: Path, annotation: str) -> None:
    (tmp_path / "guard.py").write_text(
        f"def admit(verified: {annotation}):\n    if verified is False:\n        raise PermissionError('no')\n"
    )
    assert len(_rules(tmp_path, RULE_OPTIONAL)) == 1


def test_a_branch_that_goes_on_is_no_refusal(tmp_path: Path) -> None:
    (tmp_path / "guard.py").write_text(
        "def admit(verified=None):\n"
        "    if verified is False:\n"
        "        print('note it')\n"
        "    return 'admit'\n"
    )
    assert _rules(tmp_path, RULE_OPTIONAL) == []


# -- AAK-HOOK-FAILOPEN-001: the script ---------------------------------------------------------

_FIRES = [
    "py_uncaught.py", "py_main_uncaught.py", "py_except_passes.py", "py_narrow_except.py", "py_exit_one.py",
    "py_exit_message.py", "py_return_one.py",
    "sh_errexit.sh", "sh_shebang.sh", "sh_exit_one.sh",
    "js_uncaught.mjs", "js_catch_allows.mjs", "js_exit_one.mjs",
]
_QUIET = [
    "py_wrapped.py", "py_wrapped_in_main.py", "py_deny_json.py", "py_helper_blocks.py", "py_usage.py", "py_logger.py",
    "py_allow_only.py",
    "sh_trap.sh", "sh_trap_function.sh", "sh_set_off.sh", "sh_comment.sh", "sh_usage.sh",
    "js_catch_blocks.mjs", "js_catch_helper.mjs", "js_arrow_helper.mjs", "js_uncaught_handler.mjs", "js_deny_json.mjs",
    "js_allow_only.mjs",
]
_INTERPRETERS = {".py": sys.executable, ".sh": "bash", ".mjs": "node"}


def _settings(tmp_path: Path, *handlers: dict[str, Any], event: str = "PreToolUse", name: str = "settings.json") -> None:
    target = tmp_path / ".claude" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"hooks": {event: [{"matcher": "Bash", "hooks": list(handlers)}]}}))


def _project(tmp_path: Path, script: str, **handler: Any) -> str:
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    shutil.copy(HOOKS / script, hooks / script)
    _settings(tmp_path, {"type": "command", "command": f"{_INTERPRETERS[Path(script).suffix]} .claude/hooks/{script}", **handler})
    return f".claude/hooks/{script}"


@pytest.mark.parametrize("script", _FIRES)
def test_a_gate_that_can_fail_open_fires(tmp_path: Path, script: str) -> None:
    rel = _project(tmp_path, script)
    found = _rules(tmp_path, RULE_HOOK)
    assert [f.file_path for f in found] == [rel]
    assert "fails open" in found[0].evidence
    assert ".claude/settings.json" in found[0].evidence


@pytest.mark.parametrize("script", _QUIET)
def test_a_gate_that_closes_on_failure_does_not_fire(tmp_path: Path, script: str) -> None:
    _project(tmp_path, script)
    assert _rules(tmp_path, RULE_HOOK) == []


def test_every_fixture_script_is_in_a_list() -> None:
    assert sorted(p.name for p in HOOKS.iterdir()) == sorted(_FIRES + _QUIET)


# What the rule says about a script is what the script does when it hits an error. Empty stdin
# breaks JSON parsing, `{}` breaks the field lookup, and the shell ones find no jq on an empty PATH.
@pytest.mark.parametrize("script, stdin", [
    ("py_uncaught.py", ""), ("py_main_uncaught.py", ""), ("py_except_passes.py", ""), ("py_narrow_except.py", "{}"),
    ("py_exit_one.py", ""), ("py_exit_message.py", ""), ("py_return_one.py", "[]"),
])
def test_the_scripts_it_fires_on_do_not_exit_two_on_an_error(script: str, stdin: str) -> None:
    done = subprocess.run([sys.executable, str(HOOKS / script)], input=stdin, capture_output=True, text=True, timeout=30)
    assert done.returncode != 2


@pytest.mark.parametrize("script", ["py_wrapped.py", "py_wrapped_in_main.py", "py_helper_blocks.py", "py_usage.py"])
def test_the_scripts_it_stays_quiet_on_exit_two_on_bad_input(script: str) -> None:
    done = subprocess.run([sys.executable, str(HOOKS / script)], input="", capture_output=True, text=True, timeout=30)
    assert done.returncode == 2


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("script, blocks", [
    ("js_uncaught.mjs", False), ("js_catch_allows.mjs", False), ("js_catch_blocks.mjs", True), ("js_catch_helper.mjs", True),
])
def test_node_scripts_exit_as_the_rule_says(script: str, blocks: bool) -> None:
    done = subprocess.run(["node", str(HOOKS / script)], input="", capture_output=True, text=True, timeout=30)
    assert (done.returncode == 2) is blocks


@pytest.mark.parametrize("script, blocks", [("sh_errexit.sh", False), ("sh_trap.sh", True), ("sh_trap_function.sh", True)])
def test_shell_scripts_exit_as_the_rule_says(script: str, blocks: bool, tmp_path: Path) -> None:
    bash = shutil.which("bash")
    assert bash
    # No jq on this PATH, so the first command fails with 127.
    done = subprocess.run([bash, str(HOOKS / script)], input="", capture_output=True, text=True, timeout=30,
                          env={"PATH": str(tmp_path)})
    assert (done.returncode == 2) is blocks


# -- AAK-HOOK-FAILOPEN-001: the handler --------------------------------------------------------


def test_on_failure_block_closes_the_gate(tmp_path: Path) -> None:
    _project(tmp_path, "py_uncaught.py", onFailure="block")
    assert _rules(tmp_path, RULE_HOOK) == []


@pytest.mark.parametrize("tail", ["|| exit 2", "|| { echo failed >&2; exit 2; }"])
def test_a_command_line_that_exits_two_closes_the_gate(tmp_path: Path, tail: str) -> None:
    _project(tmp_path, "py_uncaught.py")
    _settings(tmp_path, {"type": "command", "command": f"python3 .claude/hooks/py_uncaught.py {tail}"})
    assert _rules(tmp_path, RULE_HOOK) == []


@pytest.mark.parametrize("tail", ["|| true", "|| :", "|| exit 0", "; exit 0", "; true"])
@pytest.mark.parametrize("handler", [{}, {"onFailure": "block"}])
def test_a_command_line_that_swallows_the_code_fires_on_the_settings(tmp_path: Path, tail: str, handler: dict[str, str]) -> None:
    _project(tmp_path, "py_wrapped.py")
    _settings(tmp_path, {"type": "command", "command": f"python3 .claude/hooks/py_wrapped.py {tail}", **handler})
    found = _rules(tmp_path, RULE_HOOK)
    assert [f.file_path for f in found] == [".claude/settings.json"]
    assert "swallowing" in found[0].evidence
    assert found[0].line_number == 1


def test_a_logger_that_swallows_the_code_is_no_gate(tmp_path: Path) -> None:
    _project(tmp_path, "py_logger.py")
    _settings(tmp_path, {"type": "command", "command": "python3 .claude/hooks/py_logger.py || true"})
    assert _rules(tmp_path, RULE_HOOK) == []


@pytest.mark.parametrize("command", [
    '"$CLAUDE_PROJECT_DIR"/.claude/hooks/py_uncaught.py',
    "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/py_uncaught.py",
    "python3 $CLAUDE_PROJECT_DIR/.claude/hooks/py_uncaught.py --flag",
    "./.claude/hooks/py_uncaught.py",
    "timeout 5 python3 .claude/hooks/py_uncaught.py",
])
def test_the_ways_a_command_names_its_script(tmp_path: Path, command: str) -> None:
    _project(tmp_path, "py_uncaught.py")
    _settings(tmp_path, {"type": "command", "command": command})
    assert len(_rules(tmp_path, RULE_HOOK)) == 1


def test_exec_form_names_the_script_in_args(tmp_path: Path) -> None:
    _project(tmp_path, "py_uncaught.py")
    _settings(tmp_path, {"type": "command", "command": "python3", "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/py_uncaught.py"]})
    assert len(_rules(tmp_path, RULE_HOOK)) == 1


def test_a_plugin_hook_is_read_from_the_plugin_root(tmp_path: Path) -> None:
    plugin = tmp_path / "plugins" / "guard"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / "hooks").mkdir()
    shutil.copy(HOOKS / "sh_errexit.sh", plugin / "hooks" / "guard.sh")
    (plugin / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "bash ${CLAUDE_PLUGIN_ROOT}/hooks/guard.sh"},
    ]}]}}))
    assert [f.file_path for f in _rules(tmp_path, RULE_HOOK)] == ["plugins/guard/hooks/guard.sh"]


def test_another_event_is_not_read(tmp_path: Path) -> None:
    _project(tmp_path, "py_uncaught.py")
    _settings(tmp_path, {"type": "command", "command": "python3 .claude/hooks/py_uncaught.py"}, event="PostToolUse")
    assert _rules(tmp_path, RULE_HOOK) == []


def test_a_script_outside_the_project_is_not_read(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    shutil.copy(HOOKS / "py_uncaught.py", tmp_path / "py_uncaught.py")
    _settings(project, {"type": "command", "command": "python3 ../py_uncaught.py"})
    assert _rules(project, RULE_HOOK) == []


def test_a_symlink_out_of_the_project_is_not_read(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / ".claude" / "hooks").mkdir(parents=True)
    shutil.copy(HOOKS / "py_uncaught.py", tmp_path / "py_uncaught.py")
    (project / ".claude" / "hooks" / "guard.py").symlink_to(tmp_path / "py_uncaught.py")
    _settings(project, {"type": "command", "command": "python3 .claude/hooks/guard.py"})
    assert _rules(project, RULE_HOOK) == []


def test_one_finding_per_script(tmp_path: Path) -> None:
    _project(tmp_path, "py_uncaught.py")
    command = {"type": "command", "command": "python3 .claude/hooks/py_uncaught.py"}
    _settings(tmp_path, command, dict(command))
    assert len(_rules(tmp_path, RULE_HOOK)) == 1


def test_a_script_that_does_not_parse_is_not_judged(tmp_path: Path) -> None:
    (tmp_path / ".claude" / "hooks").mkdir(parents=True)
    (tmp_path / ".claude" / "hooks" / "guard.py").write_text("sys.exit(2)\nif (\n")
    _settings(tmp_path, {"type": "command", "command": "python3 .claude/hooks/guard.py"})
    assert _rules(tmp_path, RULE_HOOK) == []


# -- AAK-HOOK-FAILOPEN-001: permissions.ask ----------------------------------------------------


def _permissions(tmp_path: Path, name: str = "settings.json", **permissions: Any) -> None:
    target = tmp_path / ".claude" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"permissions": permissions}, indent=2))


_ASK = ["Bash(git push *)"]


def test_ask_with_bypass_as_the_default_fires(tmp_path: Path) -> None:
    _permissions(tmp_path, ask=_ASK, defaultMode="bypassPermissions")
    found = _rules(tmp_path, RULE_HOOK)
    assert [f.file_path for f in found] == [".claude/settings.json"]
    assert "permissions.ask" in found[0].evidence and found[0].line_number == 3


def test_ask_and_bypass_in_two_settings_files_fires(tmp_path: Path) -> None:
    _permissions(tmp_path, ask=_ASK)
    _permissions(tmp_path, "settings.local.json", defaultMode="bypassPermissions")
    assert [f.file_path for f in _rules(tmp_path, RULE_HOOK)] == [".claude/settings.json"]


@pytest.mark.parametrize("name, line", [
    ("README.md", "Run it with `claude --dangerously-skip-permissions`.\n"),
    ("CLAUDE.md", "claude --permission-mode bypassPermissions\n"),
    ("Makefile", "agent:\n\tclaude --allow-dangerously-skip-permissions\n"),
    ("package.json", '{"scripts": {"agent": "claude --dangerously-skip-permissions"}}\n'),
])
def test_ask_with_a_documented_bypass_launch_fires(tmp_path: Path, name: str, line: str) -> None:
    _permissions(tmp_path, ask=_ASK)
    (tmp_path / name).write_text(line)
    found = _rules(tmp_path, RULE_HOOK)
    assert len(found) == 1 and name in found[0].evidence


@pytest.mark.parametrize("line", [
    "Never run `claude --dangerously-skip-permissions` here.\n",
    "Do not use claude --dangerously-skip-permissions.\n",
    "This project does not use that flag.\n",
    "--dangerously-skip-permissions is a flag of another tool.\n",
])
def test_a_warning_is_no_launch(tmp_path: Path, line: str) -> None:
    _permissions(tmp_path, ask=_ASK)
    (tmp_path / "README.md").write_text(line)
    assert _rules(tmp_path, RULE_HOOK) == []


@pytest.mark.parametrize("name", ["settings.json", "settings.local.json"])
def test_bypass_turned_off_stands_the_arm_down(tmp_path: Path, name: str) -> None:
    _permissions(tmp_path, ask=_ASK, defaultMode="bypassPermissions")
    if name == "settings.json":
        _permissions(tmp_path, ask=_ASK, defaultMode="bypassPermissions", disableBypassPermissionsMode="disable")
    else:
        _permissions(tmp_path, name, disableBypassPermissionsMode="disable")
    assert _rules(tmp_path, RULE_HOOK) == []


@pytest.mark.parametrize("permissions", [
    {"ask": [], "defaultMode": "bypassPermissions"},
    {"defaultMode": "bypassPermissions"},
    {"ask": _ASK},
    {"ask": _ASK, "defaultMode": "acceptEdits"},
    {"ask": "Bash(*)", "defaultMode": "bypassPermissions"},
])
def test_the_arm_needs_both_halves(tmp_path: Path, permissions: dict[str, Any]) -> None:
    _permissions(tmp_path, **permissions)
    assert _rules(tmp_path, RULE_HOOK) == []


# -- AAK-AGENT-SUBAGENT-TOOLS-001 --------------------------------------------------------------

_WRITERS = {"mcpServers": {
    "gmail": {"command": "gmail-mcp"},
    "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/me"]},
}}


def _agent(tmp_path: Path, *frontmatter: str, rel: str = "reader.md") -> None:
    target = tmp_path / ".claude" / "agents" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    head = "\n".join(["---", "name: reader", "description: Reads code", *frontmatter, "---"])
    target.write_text(f"{head}\n\nRead the code.\n")


def _servers(tmp_path: Path, config: dict[str, Any] = _WRITERS) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(config))


@pytest.mark.parametrize("frontmatter", [
    (),
    ("tools:",),
    ("tools: *",),
    ('tools: "*"',),
    ('tools: ["*"]',),
    ("tools: mcp__*",),
    ("tools: Read, *",),
])
def test_an_open_subagent_fires(tmp_path: Path, frontmatter: tuple[str, ...]) -> None:
    _agent(tmp_path, *frontmatter)
    _servers(tmp_path)
    found = _rules(tmp_path, RULE_SUBAGENT)
    assert [f.file_path for f in found] == [".claude/agents/reader.md"]
    assert "gmail (mail)" in found[0].evidence and "files (files)" in found[0].evidence


@pytest.mark.parametrize("frontmatter", [
    ("tools: Read, Grep",),
    ("tools: [Read, Grep]",),
    ("tools: []",),
    ("tools: Read, mcp__gmail__*",),
    ("disallowedTools: mcp__*",),
    ("disallowedTools: mcp__gmail, mcp__files__*",),
    ("tools: '*'", "disallowedTools: [mcp__*]"),
])
def test_a_scoped_subagent_does_not_fire(tmp_path: Path, frontmatter: tuple[str, ...]) -> None:
    _agent(tmp_path, *frontmatter)
    _servers(tmp_path)
    assert _rules(tmp_path, RULE_SUBAGENT) == []


def test_withholding_one_server_leaves_the_other_named(tmp_path: Path) -> None:
    _agent(tmp_path, "disallowedTools: mcp__gmail")
    _servers(tmp_path)
    found = _rules(tmp_path, RULE_SUBAGENT)
    assert len(found) == 1
    assert "files (files)" in found[0].evidence and "gmail" not in found[0].evidence


def test_withholding_one_tool_withholds_no_server(tmp_path: Path) -> None:
    _agent(tmp_path, "disallowedTools: mcp__gmail__send_email")
    _servers(tmp_path, {"mcpServers": {"gmail": {"command": "gmail-mcp"}}})
    assert len(_rules(tmp_path, RULE_SUBAGENT)) == 1


@pytest.mark.parametrize("config", [
    {"mcpServers": {"acme": {"command": "node", "args": ["server.js"]}}},
    {"mcpServers": {"github": {"command": "github-mcp-server", "args": ["--read-only"]}}},
    {"mcpServers": {"github": {"command": "github-mcp-server", "env": {"GITHUB_READ_ONLY": "1"}}}},
    {"mcpServers": {"docs": {"command": "node", "args": ["/home/me/mail/server.js"]}}},
    {"mcpServers": {}},
])
def test_a_project_with_no_writing_server_does_not_fire(tmp_path: Path, config: dict[str, Any]) -> None:
    _agent(tmp_path)
    _servers(tmp_path, config)
    assert _rules(tmp_path, RULE_SUBAGENT) == []


def test_a_read_only_flag_set_to_false_counts_as_writing(tmp_path: Path) -> None:
    _agent(tmp_path)
    _servers(tmp_path, {"mcpServers": {"github": {"command": "github-mcp-server", "env": {"READ_ONLY": "false"}}}})
    assert len(_rules(tmp_path, RULE_SUBAGENT)) == 1


def test_a_server_in_settings_counts(tmp_path: Path) -> None:
    _agent(tmp_path)
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"mcpServers": {"slack": {"url": "https://mcp.slack.com/sse"}}}))
    assert "slack (chat)" in _rules(tmp_path, RULE_SUBAGENT)[0].evidence


def test_no_mcp_config_does_not_fire(tmp_path: Path) -> None:
    _agent(tmp_path)
    assert _rules(tmp_path, RULE_SUBAGENT) == []


def test_a_file_claude_code_skips_does_not_fire(tmp_path: Path) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "no_description.md").write_text("---\nname: x\n---\n\nBody.\n")
    (agents / "no_name.md").write_text("---\ndescription: x\n---\n\nBody.\n")
    (agents / "no_frontmatter.md").write_text("Body.\n")
    (agents / "bad_yaml.md").write_text("---\nname: [x\ndescription: y\n---\n")
    (agents / "notes.txt").write_text("---\nname: x\ndescription: y\n---\n")
    _servers(tmp_path)
    assert _rules(tmp_path, RULE_SUBAGENT) == []


def test_agents_in_a_subfolder_are_read(tmp_path: Path) -> None:
    _agent(tmp_path, rel="review/deep/reader.md")
    _servers(tmp_path)
    assert [f.file_path for f in _rules(tmp_path, RULE_SUBAGENT)] == [".claude/agents/review/deep/reader.md"]


def test_a_long_server_list_is_cut_and_says_so(tmp_path: Path) -> None:
    _agent(tmp_path)
    _servers(tmp_path, {"mcpServers": {f"mail{i}": {"command": "gmail-mcp"} for i in range(12)}})
    evidence = _rules(tmp_path, RULE_SUBAGENT)[0].evidence
    assert evidence.count("(mail)") == 8 and evidence.endswith("and more")


def test_scan_returns_file_paths(tmp_path: Path) -> None:
    shutil.copy(OPTIONAL / "positive_none.py", tmp_path / "guard.py")
    _project(tmp_path, "py_uncaught.py")
    _agent(tmp_path)
    _servers(tmp_path)
    _, scanned = scan(tmp_path)
    for rel in scanned:
        assert (tmp_path / rel).is_file(), rel
    assert {"guard.py", ".claude/settings.json", ".claude/hooks/py_uncaught.py", ".mcp.json", ".claude/agents/reader.md"} <= scanned
