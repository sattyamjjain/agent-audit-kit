"""Tests for AAK-STDIO-001 / CVE-2026-30615 + Ox-disclosure family."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.scanners import stdio_injection

FIX = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-30615"


def _stage(tmp_path: Path, source: Path) -> Path:
    shutil.copy(source, tmp_path / source.name)
    return tmp_path


def test_py_subprocess_shell_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "py_subprocess_shell.py")
    findings, _ = stdio_injection.scan(project)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)
    msg = next(f for f in findings if f.rule_id == "AAK-STDIO-001")
    assert "shell=True" in msg.evidence or "subprocess" in msg.evidence


def test_py_os_system_stdin_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "py_os_system_stdin.py")
    findings, _ = stdio_injection.scan(project)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)


def test_ts_execa_shell_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "ts_execa_shell.ts")
    findings, _ = stdio_injection.scan(project)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)


def test_patched_argv_allowlist_is_quiet(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "patched" / "py_argv_allowlist.py")
    findings, _ = stdio_injection.scan(project)
    assert not any(f.rule_id == "AAK-STDIO-001" for f in findings)


def test_non_mcp_python_ignored(tmp_path: Path) -> None:
    # No MCP hint → skip entirely.
    (tmp_path / "util.py").write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True).stdout\n"
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert findings == []


def test_rule_metadata_has_cve_and_owasp() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-STDIO-001"]
    assert "CVE-2026-30615" in rule.cve_references
    # STDIO command injection is OWASP MCP05 (Command Injection & Execution) and
    # ASI05 (Unexpected Code Execution). MCP01/ASI02 pinned here before did not
    # describe it.
    assert rule.owasp_mcp_references == ["MCP05:2025"]
    assert rule.owasp_agentic_references == ["ASI05"]
    assert rule.severity.value == "critical"


def test_argv_list_subprocess_no_shell_is_quiet(tmp_path: Path) -> None:
    """FP guard: `subprocess.run(["cmd", tainted])` with shell=False is the
    SAFE argv form — a tainted element is an argument, not shell injection."""
    (tmp_path / "server.py").write_text(
        "from mcp.server import FastMCP\n"
        "import subprocess\n"
        "@tool\n"
        "def run_git(args):\n"
        "    return subprocess.run(['git', 'log', args], capture_output=True)\n",
        encoding="utf-8",
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-STDIO-001" for f in findings), (
        "argv-list subprocess (shell=False) must not fire AAK-STDIO-001"
    )


def test_string_command_shell_true_still_fires(tmp_path: Path) -> None:
    """Contrast: shell=True with a tainted string command IS the sink."""
    (tmp_path / "server.py").write_text(
        "from mcp.server import FastMCP\n"
        "import subprocess\n"
        "@tool\n"
        "def run_git(args):\n"
        "    return subprocess.run(f'git log {args}', shell=True)\n",
        encoding="utf-8",
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)


# A decorator written with parentheses (`@mcp.tool()`, `@server.call_tool()`) is
# a Call node, which `_call_fqn` cannot name, and the scanner passed the Call
# itself in both arms of its conditional. Only the bare `@mcp.tool` spelling
# added a tool's parameters to the taint set.


def _stdio(tmp_path: Path, source: str) -> list[str]:
    (tmp_path / "server.py").write_text(source, encoding="utf-8")
    findings, _ = stdio_injection.scan(tmp_path)
    return [f.rule_id for f in findings]


@pytest.mark.parametrize("decorator", ["@mcp.tool()", "@mcp.tool(name='shell')", "@mcp.tool"])
def test_tool_parameter_is_caller_input_however_the_decorator_is_written(
    tmp_path: Path, decorator: str
) -> None:
    source = (
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('shell')\n\n\n"
        f"{decorator}\ndef run(command: str) -> str:\n"
        "    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n"
    )
    assert "AAK-STDIO-001" in _stdio(tmp_path, source)


def test_low_level_call_tool_arguments_are_caller_input(tmp_path: Path) -> None:
    source = (
        "import subprocess\nfrom mcp.server.lowlevel import Server\n\nserver = Server('shell')\n\n\n"
        "@server.call_tool()\nasync def handle_call_tool(name: str, arguments: dict) -> list:\n"
        "    subprocess.run(arguments['cmd'], shell=True)\n    return []\n"
    )
    assert "AAK-STDIO-001" in _stdio(tmp_path, source)


# A file whose only MCP marker is a `@tool` decorator was never read: both gates
# wrote `\b(?:...|@tool|...)\b`, and a word boundary before `@` needs a word
# character in front of it.


@pytest.mark.parametrize(("decorator", "read"), [
    ("@tool", True),
    ("@tool()", True),
    ("@toolbox", False),
])
def test_a_tool_decorator_alone_marks_a_python_file(tmp_path: Path, decorator: str, read: bool) -> None:
    source = (
        "import subprocess\n\n\n"
        f"{decorator}\ndef run(payload: str) -> str:\n"
        "    return subprocess.run(payload, shell=True, capture_output=True, text=True).stdout\n"
    )
    assert ("AAK-STDIO-001" in _stdio(tmp_path, source)) is read


@pytest.mark.parametrize(("decorator", "read"), [
    ("@tool()", True),
    ("@Tool({ name: 'run' })", True),
    ("@toolbox()", False),
])
def test_a_tool_decorator_alone_marks_a_ts_file(tmp_path: Path, decorator: str, read: bool) -> None:
    (tmp_path / "tools.ts").write_text(
        "import { execa } from 'execa';\n\n"
        f"export class Tools {{\n  {decorator}\n"
        "  run(req: any) { return execa(req.body.cmd, { shell: true }); }\n}\n",
        encoding="utf-8",
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings) is read


def test_os_execvp_of_a_tool_parameter_fires(tmp_path: Path) -> None:
    source = (
        "import os\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('shell')\n\n\n"
        "@mcp.tool()\ndef run(command: str) -> None:\n    os.execvp(command, [command])\n"
    )
    assert "AAK-STDIO-001" in _stdio(tmp_path, source)


@pytest.mark.parametrize("body", [
    # An argv list without a shell is the safe form, whatever names its items.
    "    return subprocess.run(['ls', '-la', path], capture_output=True, text=True).stdout",
    # A fixed command takes nothing from the caller.
    "    return subprocess.run('uptime', shell=True, capture_output=True, text=True).stdout",
])
def test_parenthesised_tool_without_caller_input_in_the_command_is_quiet(tmp_path: Path, body: str) -> None:
    source = (
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('shell')\n\n\n"
        f"@mcp.tool()\ndef listing(path: str) -> str:\n{body}\n"
    )
    assert "AAK-STDIO-001" not in _stdio(tmp_path, source)


# ---------------------------------------------------------------------------
# A loose last-name match (`x.run`, `x.call`, ...) needs an executor. Naming
# parenthesised tools added 68 CRITICAL findings on 1,713 real Python MCP repos
# and 33 were false, nearly all `asyncio.run(main(args))`, a database or
# LLM-tool `client.run(...)` and `registry.call(name, arguments)` dispatchers.
# ---------------------------------------------------------------------------

def _tool(imports: str, body: str) -> str:
    return (
        f"{imports}\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('t')\n\n\n"
        f"@mcp.tool()\nasync def tool(command: str, arguments: dict) -> object:\n    return {body}\n"
    )


@pytest.mark.parametrize(("imports", "body"), [
    ("import asyncio", "asyncio.run(main(command))"),
    ("from asyncio import run", "run(main(command))"),
    ("", "client.run(command, {'id': 1})"),        # a Cozo or database client
    ("", "registry.call(command, arguments)"),     # a tool dispatcher
    ("", "browser.eval(command)"),
    ("", "run(['context', command])"),             # a bare name not imported from an executor
    ("import subprocess", "subprocess.run(['git'] + command.split())"),  # an argv list
    ("import subprocess as sp", "sp.run(['ls', command])"),              # an argv list, aliased
])
def test_a_call_that_runs_no_command_is_quiet(tmp_path: Path, imports: str, body: str) -> None:
    assert "AAK-STDIO-001" not in _stdio(tmp_path, _tool(imports, body))


@pytest.mark.parametrize(("imports", "body"), [
    ("import subprocess", "subprocess.run(command, shell=True)"),
    ("import os", "os.system(command)"),
    ("import subprocess as sp", "sp.run(command, shell=True)"),
    ("from subprocess import run", "run(command, shell=True)"),
    ("from os import system", "system(command)"),
    ("", "self.shell.run(command)"),
    ("", "eval(command)"),
    ("import subprocess", "subprocess.run(['git'] + command.split(), shell=True)"),
])
def test_an_executor_call_on_a_tool_parameter_still_fires(tmp_path: Path, imports: str, body: str) -> None:
    assert "AAK-STDIO-001" in _stdio(tmp_path, _tool(imports, body))


_JS_HINT = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'


def _js(tmp_path: Path, source: str) -> list[str]:
    (tmp_path / "server.ts").write_text(_JS_HINT + source, encoding="utf-8")
    findings, _ = stdio_injection.scan(tmp_path)
    return [f.evidence for f in findings if f.rule_id == "AAK-STDIO-001"]


@pytest.mark.parametrize(("source", "fires"), [
    ("execa(req.body.cmd, { shell: true });\n", True),
    ("spawn(`${bin}`, args, { shell: true });\n", True),  # a `${}` before the options
    ("spawn(cmd, args, {\n  cwd: dir,\n  shell: true,\n});\n", True),
    ("exec(cmd, { cwd: path.resolve(dir), shell: true });\n", True),
    ("spawn(cmd, args, { shell: false });\n", False),
    ('spawn("ls", ["-la"]);\n', False),
    ("exec(`git log ${req.params.branch}`);\n", True),
    ("exec(`echo ${JSON.stringify({ q: req.body.q })}`);\n", True),  # an object in the interpolation
    ('exec("git log " + req.query.branch);\n', True),
    ("exec(`git log ${branch}`);\n", False),  # a destructured argument (the limitation)
])
def test_js_shell_and_dynamic_command_shapes(tmp_path: Path, source: str, fires: bool) -> None:
    assert bool(_js(tmp_path, source)) is fires


_CRAFTED_JS = {
    "exec-brace": "exec({" * 83_000,               # cubic before: every `{` rescanned to the end
    "exec-call": "exec(" * 100_000,                # every call's argument scan ran to the end
    "interpolations": "exec(`" + "${" * 249_000,   # every interpolation rescanned to the end
    "unterminated": "exec(`${" + "req " * 124_000,  # an unclosed template full of request names
    "whitespace": "exec(" + " " * 499_000 + "x",    # two adjacent `\s*` split the run every way
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_JS))
def test_a_crafted_js_file_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    """Just under the scanner's 512,000-byte file cap. Before, 3,600 characters of
    `exec({` took 1.6 seconds and doubling them took eight times as long, so this
    size did not finish. The bound is loose for slow CI runners; the linear scan
    takes a fraction of a second."""
    import time

    body = _CRAFTED_JS[shape]
    assert len(_JS_HINT + body) < 512_000
    started = time.perf_counter()
    _js(tmp_path, body)
    assert time.perf_counter() - started < 5.0
