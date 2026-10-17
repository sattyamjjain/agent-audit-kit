from __future__ import annotations

import ast
import sys
import textwrap
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.scanners.taint_analysis import scan


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_VULNERABLE_TOOL_PY = """\
from langchain.tools import tool

@tool
def dangerous_search(query):
    import subprocess
    subprocess.run(query, shell=True)  # AAK-TAINT-001
    eval(query)  # AAK-TAINT-002
    open(query)  # AAK-TAINT-003
    import requests
    requests.get(query)  # AAK-TAINT-004
"""

_SQL_INJECTION_TOOL_PY = """\
from langchain.tools import tool

@tool
def sql_lookup(user_input):
    import sqlite3
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(user_input)
"""

_DESERIALIZATION_TOOL_PY = """\
from langchain.tools import tool

@tool
def deserialize_data(payload):
    import pickle
    pickle.loads(payload)
    import yaml
    yaml.load(payload)
"""

_NO_TYPE_HINTS_TOOL_PY = """\
from langchain.tools import tool

@tool
def untyped_tool(query, limit, offset):
    return f"Result: {query} {limit} {offset}"
"""

_MULTI_SINK_TOOL_PY = """\
from langchain.tools import tool
import subprocess
import os
import requests

@tool
def kitchen_sink(user_input):
    subprocess.run(user_input, shell=True)
    eval(user_input)
    open(user_input)
    requests.get(user_input)
"""

_CLEAN_TOOL_PY = """\
from langchain.tools import tool

@tool
def safe_tool(query: str) -> str:
    return f"Result: {query}"
"""

_CLEAN_MCP_TOOL_PY = """\
import mcp

@mcp.tool()
def safe_mcp_tool(query: str, limit: int = 10) -> str:
    results = ["item1", "item2", "item3"]
    return ", ".join(results[:limit])
"""


def test_vulnerable_triggers_rules(tmp_path: Path) -> None:
    """Vulnerable tool functions should trigger AAK-TAINT-001 through 004."""
    (tmp_path / "vulnerable_tool.py").write_text(_VULNERABLE_TOOL_PY)
    findings, scanned = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "vulnerable_tool.py" in scanned, "vulnerable_tool.py should be in scanned files"

    assert "AAK-TAINT-001" in rule_ids, "Should detect subprocess.run(query) taint flow"
    assert "AAK-TAINT-002" in rule_ids, "Should detect eval(query) taint flow"
    assert "AAK-TAINT-003" in rule_ids, "Should detect open(query) taint flow"
    assert "AAK-TAINT-004" in rule_ids, "Should detect requests.get(query) taint flow"


def test_taint_005_sql_injection(tmp_path: Path) -> None:
    """AAK-TAINT-005: cursor.execute with user input should be flagged."""
    (tmp_path / "sql_tool.py").write_text(_SQL_INJECTION_TOOL_PY)
    findings, _ = scan(tmp_path)
    taint_005 = [f for f in findings if f.rule_id == "AAK-TAINT-005"]
    assert len(taint_005) >= 1, "SQL injection via cursor.execute should be detected"


def test_taint_006_deserialization(tmp_path: Path) -> None:
    """AAK-TAINT-006: pickle.loads / yaml.load with user input should be flagged."""
    (tmp_path / "deser_tool.py").write_text(_DESERIALIZATION_TOOL_PY)
    findings, _ = scan(tmp_path)
    taint_006 = [f for f in findings if f.rule_id == "AAK-TAINT-006"]
    assert len(taint_006) >= 1, "Unsafe deserialization should be detected"


def test_taint_007_no_type_hints(tmp_path: Path) -> None:
    """AAK-TAINT-007: @tool function with no type hints on any parameter."""
    (tmp_path / "untyped_tool.py").write_text(_NO_TYPE_HINTS_TOOL_PY)
    findings, _ = scan(tmp_path)
    taint_007 = [f for f in findings if f.rule_id == "AAK-TAINT-007"]
    assert len(taint_007) >= 1, "Tool functions with no type hints should be flagged"


def test_taint_008_multi_sink_categories(tmp_path: Path) -> None:
    """AAK-TAINT-008: Tool with >= 3 different dangerous sink categories."""
    (tmp_path / "kitchen_sink.py").write_text(_MULTI_SINK_TOOL_PY)
    findings, _ = scan(tmp_path)
    taint_008 = [f for f in findings if f.rule_id == "AAK-TAINT-008"]
    assert len(taint_008) >= 1, "Tool with 3+ sink categories should trigger AAK-TAINT-008"


def test_clean_zero_findings(tmp_path: Path) -> None:
    """Safe @tool function with type hints should produce zero findings."""
    (tmp_path / "safe_tool.py").write_text(_CLEAN_TOOL_PY)
    findings, scanned = scan(tmp_path)

    assert "safe_tool.py" in scanned
    assert len(findings) == 0, (
        f"Clean tool should produce zero findings, got: "
        f"{[(f.rule_id, f.evidence) for f in findings]}"
    )


def test_empty_or_missing(tmp_path: Path) -> None:
    """No Python files and empty Python file should produce zero findings."""
    # No .py files at all
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    assert len(scanned) == 0

    # Empty .py file
    (tmp_path / "empty.py").write_text("")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    assert "empty.py" in scanned


def test_non_tool_function_not_flagged(tmp_path: Path) -> None:
    """Functions without @tool decorator should not be analysed."""
    code = """\
import subprocess

def not_a_tool(query):
    subprocess.run(query, shell=True)
    eval(query)
"""
    (tmp_path / "regular.py").write_text(code)
    findings, scanned = scan(tmp_path)
    assert "regular.py" in scanned
    assert len(findings) == 0, (
        f"Non-tool functions should not produce findings, got: "
        f"{[f.rule_id for f in findings]}"
    )


def test_mcp_tool_decorator_recognised(tmp_path: Path) -> None:
    """@mcp.tool() decorator should be recognised as a tool function."""
    (tmp_path / "mcp_tool.py").write_text(_CLEAN_MCP_TOOL_PY)
    findings, scanned = scan(tmp_path)
    assert "mcp_tool.py" in scanned
    assert len(findings) == 0, "Clean mcp.tool should produce zero findings"


def test_mcp_tool_with_taint(tmp_path: Path) -> None:
    """@mcp.tool() with dangerous sink should be flagged."""
    code = """\
import mcp
import subprocess

@mcp.tool()
def risky_mcp_tool(cmd):
    subprocess.run(cmd, shell=True)
"""
    (tmp_path / "risky_mcp.py").write_text(code)
    findings, _ = scan(tmp_path)
    taint_001 = [f for f in findings if f.rule_id == "AAK-TAINT-001"]
    assert len(taint_001) >= 1, "mcp.tool with subprocess should trigger AAK-TAINT-001"
    # Also check AAK-TAINT-007 for missing type hints
    taint_007 = [f for f in findings if f.rule_id == "AAK-TAINT-007"]
    assert len(taint_007) >= 1, "mcp.tool with no type hints should trigger AAK-TAINT-007"


def test_server_tool_decorator_recognised(tmp_path: Path) -> None:
    """@server.tool() decorator should be recognised."""
    code = """\
import server

@server.tool()
def do_something(query: str) -> str:
    return query.upper()
"""
    (tmp_path / "server_tool.py").write_text(code)
    findings, scanned = scan(tmp_path)
    assert "server_tool.py" in scanned
    assert len(findings) == 0


def test_typed_tool_does_not_trigger_007(tmp_path: Path) -> None:
    """A tool with at least one type annotation should not trigger AAK-TAINT-007."""
    code = """\
from langchain.tools import tool

@tool
def partially_typed(query: str, limit):
    return f"Result: {query} {limit}"
"""
    (tmp_path / "partial_typed.py").write_text(code)
    findings, _ = scan(tmp_path)
    taint_007 = [f for f in findings if f.rule_id == "AAK-TAINT-007"]
    assert len(taint_007) == 0, (
        "At least one type annotation should prevent AAK-TAINT-007"
    )


def test_syntax_error_file_handled_gracefully(tmp_path: Path) -> None:
    """Files with syntax errors should be skipped without crashing."""
    (tmp_path / "broken.py").write_text("def foo(:\n    pass\n")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    # Syntax-error files are not added to scanned set (parse fails before add)
    assert "broken.py" not in scanned


def test_skip_dirs_respected(tmp_path: Path) -> None:
    """Files inside node_modules / .venv should be skipped."""
    node_dir = tmp_path / "node_modules" / "evil-pkg"
    node_dir.mkdir(parents=True)
    (node_dir / "tool.py").write_text(_VULNERABLE_TOOL_PY)

    venv_dir = tmp_path / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "tool.py").write_text(_VULNERABLE_TOOL_PY)

    findings, scanned = scan(tmp_path)
    assert len(findings) == 0, "Files in SKIP_DIRS should not be scanned"
    assert len(scanned) == 0


def test_async_tool_function(tmp_path: Path) -> None:
    """Async @tool functions should also be analysed."""
    code = """\
from langchain.tools import tool
import subprocess

@tool
async def async_dangerous(query):
    subprocess.run(query, shell=True)
"""
    (tmp_path / "async_tool.py").write_text(code)
    findings, _ = scan(tmp_path)
    taint_001 = [f for f in findings if f.rule_id == "AAK-TAINT-001"]
    assert len(taint_001) >= 1, "Async tool with subprocess should trigger AAK-TAINT-001"


# ---------------------------------------------------------------------------
# The low-level MCP SDK registers every tool through one `@server.call_tool()`
# handler, called with the tool name and the caller's `arguments` dict. It was
# not an entry point, so a command taken from `arguments` scanned clean.
# ---------------------------------------------------------------------------

_LOW_LEVEL = """\
import os
import pathlib
import pickle
import subprocess

import requests
from mcp.server.lowlevel import Server

{receiver} = Server("demo")


@{receiver}.call_tool()
async def handle_call_tool({params}) -> list:
{body}
"""


def _low_level(
    tmp_path: Path, body: str, receiver: str = "server", params: str = "name: str, arguments: dict"
) -> list[str]:
    (tmp_path / "server.py").write_text(_LOW_LEVEL.format(receiver=receiver, params=params, body=body))
    findings, _ = scan(tmp_path)
    return [f.rule_id for f in findings]


@pytest.mark.parametrize("receiver", ["server", "app"])
@pytest.mark.parametrize(("body", "rule"), [
    ('    return subprocess.run(arguments["cmd"], shell=True).returncode', "AAK-TAINT-001"),
    ('    os.execvp(arguments["prog"], [arguments["prog"]])', "AAK-TAINT-001"),
    ('    return eval(arguments.get("expr"))', "AAK-TAINT-002"),
    ('    return open(arguments.get("path", "notes.txt")).read()', "AAK-TAINT-003"),
    ('    return requests.get(arguments["url"]).text', "AAK-TAINT-004"),
    ('    return pickle.loads(arguments["blob"]["data"])', "AAK-TAINT-006"),
])
def test_low_level_call_tool_handler_is_an_entry_point(
    tmp_path: Path, receiver: str, body: str, rule: str
) -> None:
    assert rule in _low_level(tmp_path, body, receiver)


@pytest.mark.parametrize("body", [
    # A fixed command, and a value that is not the caller's.
    '    return subprocess.run("uptime", shell=True).returncode',
    '    return subprocess.run(CONFIG.get("cmd"), shell=True).returncode',
    # The item read counts, not every expression built on it.
    '    return eval(arguments["expr"].strip())',
    '    return subprocess.run(["git", "log", arguments["ref"]]).returncode',
])
def test_low_level_handler_reports_only_caller_input_reaching_a_sink(tmp_path: Path, body: str) -> None:
    assert _low_level(tmp_path, body) == []


def test_low_level_handler_is_not_held_to_the_per_tool_rules(tmp_path: Path) -> None:
    """One handler dispatches every tool, and its schema comes from list_tools.

    AAK-TAINT-007 (no type hints) and -008 (three sink categories in one tool)
    describe a single `@tool` function; on the dispatcher they would report
    the shape of the SDK rather than of any tool.
    """
    body = (
        '    os.system("tar czf /tmp/notes.tgz notes")\n'
        '    index = open("notes/index.txt").read()\n'
        '    requests.post("https://backup.example.com/upload", data=index)\n'
        "    return []"
    )
    assert _low_level(tmp_path, body, params="name, arguments") == []


# A literal first argument is the call's target: a constant URL, a fixed argv,
# a constant SQL string. A parameter elsewhere in the call is data sent to that
# fixed target, and forwarding the whole `arguments` dict to a constant URL was
# the handler entry point's one false-positive shape on real servers.


@pytest.mark.parametrize("body", [
    '    return requests.post("http://bank.example/api/pay", json=arguments).text',
    '    return requests.get("https://api.example.com/search", params=arguments).text',
    '    return subprocess.run(["pbcopy"], input=arguments["text"]).returncode',
    '    return cursor.execute("SELECT * FROM notes WHERE id = ?", arguments["id"])',
])
def test_a_call_to_a_fixed_target_is_not_reported(tmp_path: Path, body: str) -> None:
    assert _low_level(tmp_path, body) == []


@pytest.mark.parametrize(("body", "rule"), [
    # The caller chooses the URL: SSRF, however much else the call sends.
    ('    return requests.post(arguments["url"], json=arguments).text', "AAK-TAINT-004"),
    # A literal first argument proves nothing where every positional argument
    # is an operand: `os.exec*` hands them on as the new program's argv, and
    # `pathlib.Path` joins them into one path.
    ('    os.execl("/bin/sh", "sh", "-c", arguments["cmd"])', "AAK-TAINT-001"),
    ('    os.execv("/bin/sh", arguments["argv"])', "AAK-TAINT-001"),
    ('    return pathlib.Path("/srv/files", arguments["name"]).read_text()', "AAK-TAINT-003"),
])
def test_a_literal_first_argument_does_not_hide_a_caller_chosen_target(
    tmp_path: Path, body: str, rule: str
) -> None:
    assert rule in _low_level(tmp_path, body)


# Real handlers copy the input into a local first (`cmd = arguments["cmd"]`, then
# `subprocess.run(cmd, ...)`). In a `call_tool` handler such a local is followed
# for AAK-TAINT-001, -003, -004 and -006.


@pytest.mark.parametrize(("body", "rule"), [
    ('    cmd = arguments["cmd"]\n    return subprocess.run(cmd, shell=True).returncode', "AAK-TAINT-001"),
    ('    path = arguments.get("path", "notes.txt")\n    return open(path).read()', "AAK-TAINT-003"),
    ('    url: str = arguments["url"]\n    return requests.get(url).text', "AAK-TAINT-004"),
    ('    blob = arguments["blob"]\n    return pickle.loads(blob)', "AAK-TAINT-006"),
    # One link further, and an item read from a local.
    ('    opts = arguments["opts"]\n    cmd = opts["cmd"]\n    return subprocess.run(cmd, shell=True).returncode',
     "AAK-TAINT-001"),
    ('    opts = arguments\n    return open(opts["path"]).read()', "AAK-TAINT-003"),
])
def test_a_handler_local_assigned_from_the_arguments_is_followed(tmp_path: Path, body: str, rule: str) -> None:
    assert _low_level(tmp_path, body) == [rule]


@pytest.mark.parametrize("body", [
    # Reassigned from a constant, or rebuilt by a call: no longer the caller's.
    '    cmd = arguments["cmd"]\n    cmd = "uptime"\n    return subprocess.run(cmd, shell=True).returncode',
    '    cmd = arguments["cmd"]\n    cmd = shlex.quote(cmd)\n    return subprocess.run(cmd, shell=True).returncode',
    # A third link is not followed.
    '    a = arguments["a"]\n    b = a\n    c = b\n    return subprocess.run(c, shell=True).returncode',
    # The literal-target skip applies to a local as to a parameter.
    '    payload = arguments\n    return requests.post("https://api.example.com/pay", json=payload).text',
])
def test_a_handler_local_that_does_not_hold_the_arguments_is_silent(tmp_path: Path, body: str) -> None:
    assert _low_level(tmp_path, body) == []


@pytest.mark.parametrize("body", [
    '    expr = arguments["expr"]\n    return eval(expr)',
    '    sql = arguments["sql"]\n    return cursor.execute(sql)',
])
def test_aliased_eval_and_sql_sinks_are_not_followed_yet(tmp_path: Path, body: str) -> None:
    """A pending decision: on 1,713 public servers the additions were 24 of 38
    true positives for AAK-TAINT-002 and 32 of 44 for AAK-TAINT-005."""
    assert _low_level(tmp_path, body) == []


def test_a_handler_alias_finding_names_the_local(tmp_path: Path) -> None:
    body = '    cmd = arguments["cmd"]\n    return subprocess.run(cmd, shell=True).returncode'
    source = _LOW_LEVEL.format(receiver="server", params="name: str, arguments: dict", body=body)
    (tmp_path / "server.py").write_text(source)
    (finding,) = scan(tmp_path)[0]
    assert finding.rule_id == "AAK-TAINT-001"
    assert finding.evidence.endswith("via local 'cmd'")
    sink_line = next(i for i, line in enumerate(source.splitlines(), 1) if "subprocess.run(cmd" in line)
    assert finding.line_number == sink_line


def test_a_call_the_direct_rule_reports_is_not_reported_twice(tmp_path: Path) -> None:
    body = '    cmd = arguments["cmd"]\n    return subprocess.run(arguments["cmd"], cwd=cmd).returncode'
    assert _low_level(tmp_path, body) == ["AAK-TAINT-001"]


def test_a_local_in_a_tool_function_is_not_followed(tmp_path: Path) -> None:
    """Only the `call_tool` handler follows locals; `@tool` behaviour is unchanged."""
    (tmp_path / "server.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef run(command: str) -> int:\n"
        "    cmd = command\n    return subprocess.run(cmd, shell=True).returncode\n"
    )
    assert scan(tmp_path)[0] == []


# Paths: a local holds the input after an `if`, a loop, a `try` or a `match` when
# some branch that gets there leaves it holding it. A branch that returns or
# raises gets nowhere, and a loop body may run no times.


# `match` is 3.10 syntax: on 3.9 the file does not parse and the scanner skips it.
_needs_match = pytest.mark.skipif(sys.version_info < (3, 10), reason="match needs Python 3.10")


def _flow(tmp_path: Path, body: str) -> list[tuple[str, int]]:
    """(rule, line) for each finding in a handler with this body, indented for it."""
    body = textwrap.indent(textwrap.dedent(body).strip("\n"), "    ")
    (tmp_path / "server.py").write_text(
        _LOW_LEVEL.format(receiver="server", params="name: str, arguments: dict", body=body)
    )
    return sorted((f.rule_id, f.line_number or 0) for f in scan(tmp_path)[0])


@pytest.mark.parametrize(("body", "rule"), [
    # Either branch order: the branch read last no longer decides.
    ("""
     if "cmd" in arguments:
         cmd = arguments["cmd"]
     else:
         cmd = "uptime"
     return subprocess.run(cmd, shell=True).returncode
     """, "AAK-TAINT-001"),
    ("""
     if "cmd" not in arguments:
         cmd = "uptime"
     else:
         cmd = arguments["cmd"]
     return subprocess.run(cmd, shell=True).returncode
     """, "AAK-TAINT-001"),
    ("""
     try:
         path = arguments["path"]
     except KeyError:
         path = "notes.txt"
     return open(path).read()
     """, "AAK-TAINT-003"),
    # A loop body may not run, so what it assigns does not replace the input.
    ("""
     url = arguments["url"]
     for mirror in MIRRORS:
         url = mirror
     return requests.get(url).text
     """, "AAK-TAINT-004"),
    ("""
     blob = arguments["blob"]
     while False:
         blob = b""
     else:
         return pickle.loads(blob)
     """, "AAK-TAINT-006"),
    # `:=` binds like an assignment, and a starred argument is read too.
    ("""
     if not (url := arguments.get("url")):
         raise ValueError("url is required")
     return requests.get(url).text
     """, "AAK-TAINT-004"),
    ("""
     argv = arguments["argv"]
     os.execvp(*argv)
     """, "AAK-TAINT-001"),
    # One case per tool, the usual shape of a dispatcher.
    pytest.param("""
     match name:
         case "run":
             cmd = arguments["cmd"]
             return subprocess.run(cmd, shell=True).returncode
         case _:
             raise ValueError(name)
     """, "AAK-TAINT-001", marks=_needs_match),
])
def test_a_local_that_holds_the_input_on_some_path_is_followed(
    tmp_path: Path, body: str, rule: str
) -> None:
    assert [r for r, _ in _flow(tmp_path, body)] == [rule]


@pytest.mark.parametrize("body", [
    # The `else` branch never sees what the `if` branch bound.
    """
    if name == "run":
        cmd = arguments["cmd"]
    else:
        other = cmd
        subprocess.run(other, shell=True)
    """,
    # Rebound by `:=`, by a comprehension's own variable, by a `case` capture, by an
    # import and by a nested `def`.
    """
    cmd = arguments["cmd"]
    if (cmd := "uptime"):
        subprocess.run(cmd, shell=True)
    """,
    """
    cmd = arguments["cmd"]
    return [subprocess.run(cmd, shell=True) for cmd in ("uptime", "date")]
    """,
    pytest.param("""
    cmd = arguments["cmd"]
    match name:
        case str(cmd):
            subprocess.run(cmd, shell=True)
    """, marks=_needs_match),
    """
    path = arguments["path"]
    from os import path
    return open(path).read()
    """,
    """
    cmd = arguments["cmd"]
    def cmd():
        return "uptime"
    return subprocess.run(cmd, shell=True).returncode
    """,
])
def test_a_local_rebound_before_the_sink_is_silent(tmp_path: Path, body: str) -> None:
    assert _flow(tmp_path, body) == []


def test_a_local_bound_in_a_branch_that_returns_does_not_reach_past_it(tmp_path: Path) -> None:
    """The sink inside the branch is reported; the one after it, where the branch
    never gets, is not."""
    found = _flow(tmp_path, """
        if name == "run":
            cmd = arguments["cmd"]
            return [subprocess.run(cmd, shell=True)]
        return [subprocess.run(cmd, shell=True)]
        """)
    source = (tmp_path / "server.py").read_text().splitlines()
    sinks = [i for i, line in enumerate(source, 1) if "subprocess.run(cmd" in line]
    assert len(sinks) == 2
    assert found == [("AAK-TAINT-001", sinks[0])]


@pytest.mark.parametrize("body", [
    '    path = os.path.basename(arguments["path"])\n    return open(path).read()',
    '    url = validate_url(arguments["url"])\n    return requests.get(url).text',
    '    blob = arguments["blob"]\n    blob = verify_signature(blob)\n    return pickle.loads(blob)',
])
def test_a_value_passed_through_a_call_is_not_followed(tmp_path: Path, body: str) -> None:
    """There is no list of sanitisers: whatever a call returns is no longer the
    caller's value, the same as for a parameter in the direct rules."""
    assert _low_level(tmp_path, body) == []


def test_a_crafted_handler_scans_in_linear_time(tmp_path: Path) -> None:
    """Thousands of locals and branches: a join costs the names its branches
    wrote, never a copy of every local. The bound is loose for slow CI runners."""
    import time

    lines = [f'    v{i} = arguments["k{i}"]' for i in range(5_000)]
    for i in range(5_000):
        lines += [f"    if name == 'n{i}':", f'        v{i} = "fixed"', "    else:", "        pass"]
    lines.append("    return subprocess.run(v0, shell=True).returncode")
    (tmp_path / "server.py").write_text(
        _LOW_LEVEL.format(receiver="server", params="name: str, arguments: dict", body="\n".join(lines))
    )
    started = time.perf_counter()
    findings, _ = scan(tmp_path)
    assert time.perf_counter() - started < 20.0
    assert [f.rule_id for f in findings] == ["AAK-TAINT-001"]


def test_stdin_data_for_a_fixed_command_is_not_reported(tmp_path: Path) -> None:
    """The base's own false positive of this shape, in a FastMCP tool."""
    (tmp_path / "server.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef copy(text: str) -> int:\n"
        "    return subprocess.run(['pbcopy'], input=text).returncode\n"
    )
    assert scan(tmp_path)[0] == []


def test_os_exec_runs_a_tool_parameter(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import os\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef run(command: str) -> None:\n    os.execvp(command, [command])\n"
    )
    findings, _ = scan(tmp_path)
    assert [f.rule_id for f in findings] == ["AAK-TAINT-001"]
    assert "os.execvp()" in findings[0].evidence


def test_os_exec_of_a_fixed_program_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import os\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef restart(reason: str) -> None:\n    os.execv('/usr/bin/uptime', ['uptime'])\n"
    )
    assert scan(tmp_path)[0] == []


def test_an_item_read_from_a_tool_parameter_is_the_parameter(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef run(options: dict) -> int:\n"
        "    return subprocess.run(options['cmd'], shell=True).returncode\n"
    )
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-001"]


# ---------------------------------------------------------------------------
# AAK-TAINT-002 is not reported for a calculator `@tool` whose expression has
# passed, in straight-line code before the call, an allow-list check that
# admits no letter or underscore (see the block comment above
# `_allow_listed_sinks`). Every other shape is reported as before, and each
# reported case below is kept so by one condition of that reading.
# ---------------------------------------------------------------------------

_CALC_HEAD = '''\
import contextlib
import re

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")
OPERATORS = set("0123456789+-*/(). ")
'''
_CALC_DEF = '''

@mcp.tool()
def calc(expression: str, more: list, extra: str = "") -> object:
'''
_CHECK = 'if not set(expression) <= OPERATORS:\n    raise ValueError(expression)\n'


def _calc(tmp_path: Path, body: str, module: str = "") -> list[str]:
    """Rule ids for `calc(expression, more, extra)` with `body`, after `module` code."""
    body = textwrap.indent(textwrap.dedent(body).strip("\n"), "    ")
    source = _CALC_HEAD + textwrap.dedent(module) + _CALC_DEF + body + "\n"
    (tmp_path / "server.py").write_text(source)
    return [f.rule_id for f in scan(tmp_path)[0]]


_SILENCED = {
    "inline string": """
        if not all(c in "0123456789+-*/(). " for c in expression):
            raise ValueError(expression)
        return eval(expression)
    """,
    "local set": """
        allowed = set("0123456789+-*/(). ")
        if not all(c in allowed for c in expression):
            return "invalid characters"
        return eval(expression)
    """,
    "module constant": """
        if not all(c in OPERATORS for c in expression):
            return None
        return eval(expression)
    """,
    "set inclusion": """
        allowed = set("0123456789+-*/(). ")
        if not set(expression) <= allowed:
            return "invalid characters"
        return eval(expression, {"__builtins__": {}}, {})
    """,
    "full match": """
        if not re.fullmatch(r"[0-9.\\-+*/()\\t ]+", expression):
            raise ValueError("only arithmetic")
        return eval(expression)
    """,
    "anchored full match": """
        if not re.fullmatch(r"^[0-9+*/() -]*$", expression):
            raise ValueError("only arithmetic")
        return eval(expression)
    """,
    "call in the passing branch": """
        allowed_chars = "0123456789+-*/(). "
        if all(c in allowed_chars for c in expression):
            return str(eval(expression))
        return "invalid characters"
    """,
    "call in the else of a check that exits": """
        if not set(expression) <= OPERATORS:
            raise ValueError(expression)
        else:
            return eval(expression)
    """,
    "one try body holding both": """
        try:
            allowed_chars = set("0123456789+-*/.() ")
            if not all(c in allowed_chars for c in expression):
                raise ValueError("invalid characters")
            return eval(expression)
        except Exception as exc:
            return str(exc)
    """,
    "check first, call in a later try": """
        allowed = set("0123456789+-*/(). %")
        if not set(expression) <= allowed:
            return "invalid characters"
        try:
            return str(eval(expression, {"__builtins__": {}}, {}))
        except Exception as exc:
            return str(exc)
    """,
    "exec and compile": """
        if not all(c in OPERATORS for c in expression):
            return None
        exec(expression)
        return compile(expression, "<calc>", "eval")
    """,
    "frozenset local": """
        digits = frozenset("0123456789+")
        if not all(c in digits for c in expression):
            return None
        return eval(expression)
    """,
    "tuple local": """
        symbols = ("1", "2", "+", " ")
        if not all(c in symbols for c in expression):
            return None
        return eval(expression)
    """,
    "annotated local": """
        allowed: set = set("0123456789+")
        if not set(expression) <= allowed:
            return None
        return eval(expression)
    """,
    "empty allow-list": """
        if not all(c in [] for c in expression):
            return None
        return eval(expression)
    """,
    "call in another if's test": """
        if not set(expression) <= OPERATORS:
            raise ValueError(expression)
        if eval(expression) > 100:
            return "large"
        return "small"
    """,
    "check in the branch of another check": """
        if all(c in OPERATORS for c in extra):
            if not set(expression) <= OPERATORS:
                raise ValueError(expression)
            return eval(expression)
        return None
    """,
}


@pytest.mark.parametrize("body", list(_SILENCED.values()), ids=list(_SILENCED))
def test_eval_behind_an_arithmetic_allow_list_is_not_reported(tmp_path: Path, body: str) -> None:
    assert _calc(tmp_path, body) == []


def test_the_same_call_without_the_check_is_reported(tmp_path: Path) -> None:
    assert _calc(tmp_path, "return eval(expression)") == ["AAK-TAINT-002"]


# The review of the first version of this skip, which read every path through
# the function: each tool reached `eval` with unchecked input while the rule
# stayed silent. All of them are reported again.
_REVIEW_REPROS = {
    "comprehension rebinds the parameter": ("", """
        if not re.fullmatch(r"[0-9+*/() -]+", expression):
            raise ValueError("bad")
        return [eval(expression) for expression in more]
    """),
    "loop back-edge": ("", """
        if not re.fullmatch(r"[0-9+*/() -]+", expression):
            raise ValueError("bad")
        out = []
        for item in more:
            out.append(eval(expression))
            expression = item
        return out
    """),
    "while test": ("", """
        if not re.fullmatch(r"[0-9+*/() -]+", expression):
            raise ValueError("bad")
        while eval(expression):
            expression = more.pop()
        return None
    """),
    "with suppress swallows the check": ("", """
        with contextlib.suppress(ValueError):
            if not re.fullmatch(r"[0-9+*/() -]+", expression):
                raise ValueError("bad")
        return eval(expression)
    """),
    "finally after a failed check": ("", """
        try:
            if not re.fullmatch(r"[0-9+*/() -]+", expression):
                raise ValueError("bad")
        finally:
            result = eval(expression)
        return result
    """),
    "except after a rebinding": ("", """
        if not re.fullmatch(r"[0-9+*/() -]+", expression):
            raise ValueError("bad")
        try:
            expression = extra
            if not re.fullmatch(r"[0-9+*/() -]+", expression):
                raise ValueError("bad fallback")
            result = eval(expression)
        except ValueError:
            result = eval(expression)
        return result
    """),
    "compiled pattern with pos and endpos": ("SAFE = re.compile(r'[0-9+*/() -]+')\n", """
        if not SAFE.fullmatch(expression, 0, 1):
            raise ValueError("bad")
        return eval(expression)
    """),
    "allow-list rebound by another tool": ('''

        @mcp.tool()
        def set_allowed(chars: str) -> None:
            global OPERATORS
            OPERATORS = set(chars)
    ''', """
        if not set(expression) <= OPERATORS:
            raise ValueError("bad")
        return eval(expression)
    """),
    "allow-list widened by the caller": ("", """
        OPERATORS.update(extra)
        if not set(expression) <= OPERATORS:
            raise ValueError("bad")
        return eval(expression)
    """),
    "local allow-list widened by the caller": ("", """
        allowed = set("0123456789+-*/(). ")
        allowed.update(extra)
        if not set(expression) <= allowed:
            raise ValueError("bad")
        return eval(expression)
    """),
    "is not None on a bool": ("", """
        if expression.isdigit() is not None:
            return eval(expression)
        return None
    """),
    "walrus rebinding inside the check": ("", """
        if re.fullmatch(r"[0-9+*/() -]+", expression) and (expression := extra):
            return eval(expression)
        return None
    """),
    "multiline flag through a name": ("FLAGS = re.M\n", """
        if not re.match(r"^[0-9+*/() -]+$", expression, FLAGS):
            raise ValueError("bad")
        exec(expression)
    """),
    "verbose comment hides the anchor": ("", """
        if not re.match(r"^[0-9+*/() -]+  # digits and operators only$", expression, re.X):
            raise ValueError("bad")
        return eval(expression)
    """),
    "negated non-space search": ("", """
        if re.search(r"[^\\S]", expression):
            raise ValueError("no whitespace")
        return eval(expression)
    """),
    "generator consumed after a rebinding": ("", """
        if not re.fullmatch(r"[0-9+*/() -]+", expression):
            raise ValueError("bad")
        pending = (eval(expression) for _ in range(1))
        expression = extra
        return list(pending)
    """),
}


@pytest.mark.parametrize(("module", "body"), list(_REVIEW_REPROS.values()), ids=list(_REVIEW_REPROS))
def test_the_review_repros_are_reported(tmp_path: Path, module: str, body: str) -> None:
    findings = _calc(tmp_path, body, module)
    assert findings and set(findings) == {"AAK-TAINT-002"}


def test_an_enclosing_function_that_shadows_the_allow_list_is_reported(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(_CALC_HEAD + textwrap.dedent('''

        def build(config: dict) -> FastMCP:
            OPERATORS = set(config["chars"])

            @mcp.tool()
            def calc(expression: str) -> object:
                if not set(expression) <= OPERATORS:
                    raise ValueError("bad")
                return eval(expression)

            return mcp
    '''))
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-002"]


_HANDLER = '''\
import re

from mcp.server.lowlevel import Server

server = Server("demo")
P = r"[0-9+*/() -]+"


@server.call_tool()
async def handle(name: str, arguments: dict) -> list:
'''


@pytest.mark.parametrize("body", [
    # A `call_tool` handler is not read at all, so a clean check is reported too.
    """
    if not re.fullmatch(P, arguments["expr"]):
        raise ValueError("only arithmetic")
    return [eval(arguments["expr"])]
    """,
    # The review's handler repros.
    """
    if not re.fullmatch(P, arguments.get("expr", "")):
        raise ValueError("only arithmetic")
    arguments["expr"] = arguments["other"]
    return [eval(arguments["expr"])]
    """,
    """
    if not re.fullmatch(P, arguments.get("expr", "")):
        raise ValueError("only arithmetic")
    arguments.update(arguments.get("overrides", {}))
    return [eval(arguments["expr"])]
    """,
    """
    if not re.fullmatch(P, arguments.get("expr", "")):
        raise ValueError("only arithmetic")
    params = arguments
    params["expr"] = params["other"]
    return [eval(arguments["expr"])]
    """,
    """
    if not re.fullmatch(r"[0-9+*/() -]*", arguments.get("expr", "")):
        raise ValueError("only arithmetic")
    return [eval(arguments.get("expr", arguments["fallback"]))]
    """,
], ids=["clean check", "item assigned", "dict updated", "alias item assigned", "different default"])
def test_a_call_tool_handler_is_not_read_by_the_skip(tmp_path: Path, body: str) -> None:
    (tmp_path / "server.py").write_text(_HANDLER + textwrap.indent(textwrap.dedent(body).strip("\n"), "    ") + "\n")
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-002"]


_MATCH_NEEDS_310 = pytest.mark.skipif(sys.version_info < (3, 10), reason="match needs Python 3.10")

# Each body is reported for one reason, named by its id, that the reading
# above requires. `_CHECK` is a check the skip reads.
_GUARDS = {
    # Where the call is.
    "call in a list comprehension": _CHECK + "return [eval(expression) for _ in more]",
    "call in a generator": _CHECK + "return list(eval(expression) for _ in more)",
    "call in a lambda": _CHECK + "return (lambda: eval(expression))()",
    "call in a loop body": _CHECK + "for _ in more:\n    eval(expression)",
    "call in a while test": _CHECK + "while eval(expression):\n    break",
    "call in a with body": _CHECK + "with contextlib.suppress():\n    return eval(expression)",
    "call in an except": _CHECK + "try:\n    return len(more)\nexcept Exception:\n    return eval(expression)",
    "call in a try's else": _CHECK + "try:\n    n = len(more)\nexcept Exception:\n    n = 0\nelse:\n    return eval(expression)",
    "call in a finally": _CHECK + "try:\n    n = len(more)\nfinally:\n    eval(expression)",
    "call in a default of a nested def": _CHECK + "def later(value=eval(expression)):\n    return value",
    "call in the failing branch": "if not set(expression) <= OPERATORS:\n    return eval(expression)",
    "call in the else of a passing check": (
        "if set(expression) <= OPERATORS:\n    pass\nelse:\n    return eval(expression)"
    ),
    "call in another if": _CHECK + "if extra:\n    return eval(expression)",
    "a passing check whose body falls through": (
        "if all(c in OPERATORS for c in expression):\n    pass\nreturn eval(expression)"
    ),
    "call before the check": "result = eval(expression)\n" + _CHECK + "return result",
    "a parameter that was not checked": _CHECK + "return eval(extra)",
    "another argument reads a parameter": _CHECK + 'return eval(expression, {"more": more})',
    "a keyword reads a parameter": _CHECK + 'return compile(expression, "<calc>", "eval", dont_inherit=bool(more))',
    # Where the check is.
    "check body falls through": "if not set(expression) <= OPERATORS:\n    print('bad')\nreturn eval(expression)",
    "check inside another if": "if extra:\n" + textwrap.indent(_CHECK, "    ") + "return eval(expression)",
    "check in a try, call after it": (
        "try:\n" + textwrap.indent(_CHECK, "    ") + "except ValueError:\n    pass\nreturn eval(expression)"
    ),
    # What sits between them.
    "a loop between": _CHECK + "for _ in more:\n    pass\nreturn eval(expression)",
    "a try between": _CHECK + "try:\n    n = len(more)\nexcept Exception:\n    n = 0\nreturn eval(expression)",
    "a with between": _CHECK + "with contextlib.suppress():\n    pass\nreturn eval(expression)",
    "a comprehension between": _CHECK + "sizes = [len(m) for m in more]\nreturn eval(expression)",
    "a lambda between": _CHECK + "key = lambda m: m\nreturn eval(expression)",
    "a def between": _CHECK + "def helper():\n    return 1\nreturn eval(expression)",
    "a class between": _CHECK + "class Box:\n    pass\nreturn eval(expression)",
    "a yield between": _CHECK + "yield None\nyield eval(expression)",
    "a loop inside an if between": _CHECK + "if extra:\n    for _ in more:\n        pass\nreturn eval(expression)",
    "a loop in a passing branch between": (
        _CHECK + "if all(c in OPERATORS for c in extra):\n    for _ in more:\n        pass\nreturn eval(expression)"
    ),
    "a loop in the else of a passing check": (
        _CHECK + "if all(c in OPERATORS for c in extra):\n    pass\nelse:\n    for _ in more:\n        pass\n"
        "return eval(expression)"
    ),
    "a loop in the else of a check that exits": (
        "if not set(expression) <= OPERATORS:\n    raise ValueError(expression)\nelse:\n"
        "    for _ in more:\n        pass\nreturn eval(expression)"
    ),
    # The parameter, bound or used again anywhere, here after the call.
    "assigned": _CHECK + "result = eval(expression)\nexpression = extra\nreturn result",
    "augmented": _CHECK + "result = eval(expression)\nexpression += extra\nreturn result",
    "annotated": _CHECK + "result = eval(expression)\nexpression: str = extra\nreturn result",
    "deleted": _CHECK + "result = eval(expression)\ndel expression\nreturn result",
    "a for target": _CHECK + "result = eval(expression)\nfor expression in more:\n    pass\nreturn result",
    "a with target": (
        _CHECK + "result = eval(expression)\nwith contextlib.suppress() as expression:\n    pass\nreturn result"
    ),
    "an except name": (
        _CHECK + "result = eval(expression)\ntry:\n    pass\nexcept Exception as expression:\n    pass\nreturn result"
    ),
    "a walrus target": _CHECK + "result = eval(expression)\n(expression := extra)\nreturn result",
    "a comprehension target": _CHECK + "result = eval(expression)\n[1 for expression in more]\nreturn result",
    "an import": _CHECK + "result = eval(expression)\nimport os as expression\nreturn result",
    "a def name": _CHECK + "result = eval(expression)\ndef expression():\n    pass\nreturn result",
    "a class name": _CHECK + "result = eval(expression)\nclass expression:\n    pass\nreturn result",
    "a nested function's parameter": (
        _CHECK + "result = eval(expression)\ndef helper(expression):\n    return expression\nreturn result"
    ),
    "a lambda parameter": _CHECK + "result = eval(expression)\nkey = lambda expression: expression\nreturn result",
    "nonlocal in a nested function": (
        _CHECK + "result = eval(expression)\ndef widen():\n    nonlocal expression\n    expression = extra\n"
        "return result"
    ),
    "a match capture": pytest.param(
        _CHECK + "result = eval(expression)\nmatch extra:\n    case expression:\n        pass\nreturn result",
        marks=_MATCH_NEEDS_310,
    ),
    "a match star capture": pytest.param(
        _CHECK + "result = eval(expression)\nmatch more:\n    case [*expression]:\n        pass\nreturn result",
        marks=_MATCH_NEEDS_310,
    ),
    "a match mapping rest": pytest.param(
        _CHECK + "result = eval(expression)\nmatch more:\n    case {**expression}:\n        pass\nreturn result",
        marks=_MATCH_NEEDS_310,
    ),
    "a type parameter": pytest.param(
        _CHECK + "result = eval(expression)\nclass Box[expression]:\n    pass\nreturn result",
        marks=pytest.mark.skipif(sys.version_info < (3, 12), reason="type parameters need Python 3.12"),
    ),
    "assigned to another name": _CHECK + "result = eval(expression)\nalias = expression\nreturn result",
    "unpacked to another name": _CHECK + "result = eval(expression)\nfirst, second = expression, extra\nreturn result",
    "a with item": _CHECK + "result = eval(expression)\nwith expression:\n    pass\nreturn result",
    "a method called on it": _CHECK + "result = eval(expression)\nprint(expression.upper())\nreturn result",
    "an item read": _CHECK + "result = eval(expression)\nprint(expression[0])\nreturn result",
    # The check.
    "a check on a copy": "if not all(c in OPERATORS for c in str(expression)):\n    raise ValueError\nreturn eval(expression)",
    "a set of a copy": "if not set(str(expression)) <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "a full match on a copy": (
        "if not re.fullmatch(r'[0-9+]+', str(expression)):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a check on a stripped copy": (
        "if not all(c in OPERATORS for c in expression.strip()):\n    raise ValueError\nreturn eval(expression)"
    ),
    "any() of a negated test": "if any(c not in OPERATORS for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "issubset": "if not set(expression).issubset(OPERATORS):\n    raise ValueError\nreturn eval(expression)",
    "isdigit": "if not expression.isdigit():\n    raise ValueError\nreturn eval(expression)",
    "membership of the whole value": "if expression not in ('1+1', '2*3'):\n    raise ValueError\nreturn eval(expression)",
    "double negation": "if not not all(c in OPERATORS for c in expression):\n    return eval(expression)\nreturn None",
    "a filtered generator": (
        "if not all(c in OPERATORS for c in expression if c != ' '):\n    raise ValueError\nreturn eval(expression)"
    ),
    "two for clauses": (
        "if not all(c in OPERATORS for c in expression for _ in more):\n    raise ValueError\n"
        "return eval(expression)"
    ),
    "a list in all()": "if not all([c in OPERATORS for c in expression]):\n    raise ValueError\nreturn eval(expression)",
    "all() with a keyword": (
        "if not all((c in OPERATORS for c in expression), **{}):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a target that is not a name": (
        "if not all(c in OPERATORS for c, in expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "an element other than the target": (
        "if not all(extra in OPERATORS for c in expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "the target as the allow-list": "if not all(c in c for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "not in": "if not all(c not in OPERATORS for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "a chained comparison": (
        "if not all(c in OPERATORS != more for c in expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a proper subset": "if not set(expression) < OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "a chained set comparison": "if not set(expression) <= OPERATORS <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "frozenset of the value": "if not frozenset(expression) <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "set() with a keyword": "if not set(expression, **{}) <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "a full match with flags": (
        "if not re.fullmatch(r'[0-9+]+', expression, re.ASCII):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a full match by keyword": (
        "if not re.fullmatch(r'[0-9+]+', string=expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "re.match": "if not re.match(r'[0-9+]+$', expression):\n    raise ValueError\nreturn eval(expression)",
    "re.search": "if not re.search(r'^[0-9+]+$', expression):\n    raise ValueError\nreturn eval(expression)",
    "another module's fullmatch": (
        "if not contextlib.fullmatch(r'[0-9+]+', expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a pattern held in a name": (
        "if not re.fullmatch(OPERATORS, expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a bytes pattern": "if not re.fullmatch(rb'[0-9+]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a full match with a flags keyword": (
        "if not re.fullmatch(r'[0-9+]+', expression, flags=re.A):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a method of a compiled pattern": (
        "if not re.compile(r'[0-9+]+').fullmatch(expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "any() of a membership test": (
        "if not any(c in OPERATORS for c in expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "all() with two arguments": (
        "if not all((c in OPERATORS for c in expression), extra):\n    raise ValueError\nreturn eval(expression)"
    ),
    "an element that is not a comparison": "if not all(c for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "a constant on the left": "if not all('1' in c for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "the value compared itself": "if not expression <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "an attribute's set()": "if not builtins.set(expression) <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "set() of nothing": "if not set() <= OPERATORS:\n    raise ValueError\nreturn eval(expression)",
    "a set compared with a parameter's": (
        "if not set(expression) <= set(extra):\n    raise ValueError\nreturn eval(expression)"
    ),
    # The allow-list.
    "a parameter as the allow-list": "if not all(c in extra for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "a local bound twice": (
        "allowed = set('0123')\nallowed = set('0123456789')\n"
        "if not set(expression) <= allowed:\n    raise ValueError\nreturn eval(expression)"
    ),
    "a local bound in another if": (
        "if extra:\n    allowed = set('0123')\nif not set(expression) <= allowed:\n    raise ValueError\n"
        "return eval(expression)"
    ),
    "a local passed to a call": (
        "allowed = set('0123')\nprint(allowed)\nif not set(expression) <= allowed:\n    raise ValueError\n"
        "return eval(expression)"
    ),
    "a local built from a parameter": (
        "allowed = set(extra)\nif not set(expression) <= allowed:\n    raise ValueError\nreturn eval(expression)"
    ),
    "a local joined with a parameter": (
        "allowed = '0123' + extra\nif not all(c in allowed for c in expression):\n    raise ValueError\n"
        "return eval(expression)"
    ),
    "a local set() with a keyword": (
        "allowed = set('0123', **{})\nif not set(expression) <= allowed:\n    raise ValueError\nreturn eval(expression)"
    ),
    "a local declared global": (
        "global allowed\nallowed = set('0123')\nif not set(expression) <= allowed:\n    raise ValueError\n"
        "return eval(expression)"
    ),
    "a local rebound by a nested function": (
        "allowed = set('0123')\nif not set(expression) <= allowed:\n    raise ValueError\nresult = eval(expression)\n"
        "def widen():\n    nonlocal allowed\n    allowed = set(extra)\nreturn result"
    ),
    "a local built by another call": (
        "allowed = load('0123')\nif not set(expression) <= allowed:\n    raise ValueError\nreturn eval(expression)"
    ),
    "a local set() of two strings": (
        "allowed = set('0123', '4')\nif not set(expression) <= allowed:\n    raise ValueError\nreturn eval(expression)"
    ),
    "a local bound with another name": (
        "allowed = alias = set('0123')\nalias.add(extra)\nif not set(expression) <= allowed:\n    raise ValueError\n"
        "return eval(expression)"
    ),
    "a local reached past a comprehension": (
        "allowed = set('0123')\nsizes = [len(m) for m in more]\nif not set(expression) <= allowed:\n"
        "    raise ValueError\nreturn eval(expression)"
    ),
    "a local reached past a loop": (
        "allowed = set('0123')\nfor _ in more:\n    pass\nif not set(expression) <= allowed:\n    raise ValueError\n"
        "return eval(expression)"
    ),
    # What the allow-list admits.
    "letters": "if not all(c in '0123456789abcdef' for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "an underscore": "if not all(c in '0123456789_' for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "a non-ASCII digit": (
        "if not all(c in '0123456789\\u0663' for c in expression):\n    raise ValueError\nreturn eval(expression)"
    ),
    "a letter in a set": "if not all(c in {'1', 'x'} for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "a number in a set": "if not all(c in {'1', 2} for c in expression):\n    raise ValueError\nreturn eval(expression)",
    "a word class": "if not re.fullmatch(r'[\\w+]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a digit class": "if not re.fullmatch(r'[\\d+]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "an escape code": "if not re.fullmatch(r'[\\x30-\\x39]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a range over letters": "if not re.fullmatch(r'[+-~]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a range ending in a letter": "if not re.fullmatch(r'[0-z]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a reversed range": "if not re.fullmatch(r'[9-0]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a letter range": "if not re.fullmatch(r'[a-f0-9]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a negated class": "if not re.fullmatch(r'[^a-z]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a class opening with ]": "if not re.fullmatch(r'[]0-9]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a bracket inside the class": "if not re.fullmatch(r'[0-9[]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "two classes": "if not re.fullmatch(r'[0-9]+[*]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "no repeat": "if not re.fullmatch(r'[0-9+]', expression):\n    raise ValueError\nreturn eval(expression)",
    "an alternation": "if not re.fullmatch(r'[0-9]+|[a-z]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "an escaped dollar": "if not re.fullmatch(r'[0-9]+\\$', expression):\n    raise ValueError\nreturn eval(expression)",
    "a trailing backslash": "if not re.fullmatch(r'[0-9\\]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "an octal escape": "if not re.fullmatch(r'[0-9\\137]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a letter in the class": "if not re.fullmatch(r'[0-9a]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a negated class of digits": "if not re.fullmatch(r'[^0-9]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "no opening bracket": "if not re.fullmatch(r'x0-9]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a group around the class": "if not re.fullmatch(r'([0-9]+)', expression):\n    raise ValueError\nreturn eval(expression)",
    "an empty class": "if not re.fullmatch(r'[]+', expression):\n    raise ValueError\nreturn eval(expression)",
    "a range to an escape code": "if not re.fullmatch(r'[0-\\x39]+', expression):\n    raise ValueError\nreturn eval(expression)",
}


@pytest.mark.parametrize("body", list(_GUARDS.values()), ids=list(_GUARDS))
def test_a_shape_the_skip_does_not_read_is_reported(tmp_path: Path, body: str) -> None:
    findings = _calc(tmp_path, body)
    assert findings and set(findings) == {"AAK-TAINT-002"}


# Module code that can change what a check means, with the check forms it
# keeps reported. Every other form is still read, so the guard is no broader.
_MODULE_GUARDS = {
    "constant bound twice": ("OPERATORS = set('0123456789+-*/')\n", {"all", "set"}),
    "constant declared global in a function": ("\n\ndef reset() -> None:\n    global OPERATORS\n", {"all", "set"}),
    "constant mutated in a function": ("\n\ndef widen(chars: str) -> None:\n    OPERATORS.add(chars)\n", {"all", "set"}),
    "constant read outside a comparison": ("PRINTABLE = sorted(OPERATORS)\n", {"all", "set"}),
    "a star import": ("from helpers import *\n", {"all", "set", "fullmatch"}),
    "all rebound": ("all = any\n", {"all"}),
    "set rebound": ("set = frozenset\n", {"all", "set"}),
    "eval rebound": ("\n\ndef eval(source: str) -> str:\n    return source\n", {"all", "set", "fullmatch"}),
    "re rebound": ("re = None\n", {"fullmatch"}),
    "a function of re replaced": ("re.fullmatch = lambda pattern, string: True\n", {"fullmatch"}),
}
_CHECK_FORMS = {
    "all": "if not all(c in OPERATORS for c in expression):",
    "set": "if not set(expression) <= OPERATORS:",
    "fullmatch": "if not re.fullmatch(r'[0-9+*/() -]+', expression):",
}


@pytest.mark.parametrize("form", list(_CHECK_FORMS))
@pytest.mark.parametrize("guard", list(_MODULE_GUARDS))
def test_module_code_that_can_change_a_check_keeps_it_reported(tmp_path: Path, guard: str, form: str) -> None:
    module, affected = _MODULE_GUARDS[guard]
    findings = _calc(tmp_path, f"{_CHECK_FORMS[form]}\n    raise ValueError\nreturn eval(expression)", module)
    assert findings == (["AAK-TAINT-002"] if form in affected else [])


def test_a_module_constant_that_admits_letters_is_reported(tmp_path: Path) -> None:
    body = "if not all(c in HEX for c in expression):\n    raise ValueError\nreturn eval(expression)"
    assert _calc(tmp_path, body, "HEX = '0123456789abcdef'\n") == ["AAK-TAINT-002"]
    assert _calc(tmp_path, body, "HEX = '0123456789+-'\n") == []


@pytest.mark.parametrize(("signature", "reported"), [
    ("def calc(*, expression: str) -> object:", False),
    ("def calc(expression: str, /) -> object:", False),
    ("def calc(*expression: str) -> object:", True),
], ids=["keyword-only", "positional-only", "varargs"])
def test_which_parameters_the_skip_reads(tmp_path: Path, signature: str, reported: bool) -> None:
    (tmp_path / "server.py").write_text(
        _CALC_HEAD + "\n\n@mcp.tool()\n" + signature + "\n"
        "    if not all(c in OPERATORS for c in expression):\n        raise ValueError\n"
        "    return eval(expression)\n"
    )
    assert ("AAK-TAINT-002" in [f.rule_id for f in scan(tmp_path)[0]]) is reported


def test_an_async_tool_is_read_but_not_an_async_generator_check(tmp_path: Path) -> None:
    head = _CALC_HEAD + "\n\n@mcp.tool()\nasync def calc(expression: str) -> object:\n"
    check = "    if not all(c in OPERATORS {}for c in expression):\n        raise ValueError\n    return eval(expression)\n"
    (tmp_path / "server.py").write_text(head + check.format(""))
    assert scan(tmp_path)[0] == []
    (tmp_path / "server.py").write_text(head + check.format("async "))
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-002"]


def test_re_imported_only_inside_the_tool_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef calc(expression: str) -> object:\n    import re\n"
        "    if not re.fullmatch(r'[0-9+*/() -]+', expression):\n        raise ValueError\n"
        "    return eval(expression)\n"
    )
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-002"]


def test_the_skip_leaves_the_other_rules_alone(tmp_path: Path) -> None:
    """Only AAK-TAINT-002 reads the check: an allow-listed path still reaches `open`."""
    assert _calc(tmp_path, _CHECK + "return open(expression).read()") == ["AAK-TAINT-003"]


def test_a_function_too_deep_to_read_is_reported_and_the_scan_goes_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_audit_kit.scanners import taint_analysis

    def too_deep(*_args: object) -> frozenset[int]:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(taint_analysis, "_read_allow_listed_sinks", too_deep)
    (tmp_path / "other.py").write_text(
        "import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef run(command: str) -> int:\n    return subprocess.run(command, shell=True).returncode\n"
    )
    findings = _calc(tmp_path, _CHECK + "return eval(expression)")
    assert sorted(findings) == ["AAK-TAINT-001", "AAK-TAINT-002"]


# Past the 1,000-frame recursion limit, so a recursive walk would raise, and
# inside what every supported Python parses: 3.11 builds an AST three levels per
# frame left under that limit, about 2,600 levels from where pytest runs a test.
_EVERY_PARSER_DEPTH = 2_000


@pytest.mark.parametrize(("shape", "depth"), [
    ("not", _EVERY_PARSER_DEPTH),
    ("plus", _EVERY_PARSER_DEPTH),
    # Deeper than 3.11 parses; 3.9, 3.10 and 3.12 build both.
    ("not", 3_000),
    ("plus", 5_000),
])
def test_a_crafted_check_does_not_exhaust_the_stack(tmp_path: Path, shape: str, depth: int) -> None:
    """Neither shape needs brackets, so the parser's 200-deep limit does not stop
    them. The skip reads one `not` and no `+` chain, so the call is reported as
    before, and nothing on the way walks the check by recursion."""
    if shape == "not":
        test_expr = "not " * depth + "set(expression) <= OPERATORS"
    else:
        test_expr = "expression in " + " + ".join(['"0123456789"'] * depth)
    body = f"if {test_expr}:\n    return eval(expression)"
    assert depth > sys.getrecursionlimit()
    if depth > _EVERY_PARSER_DEPTH:
        try:
            ast.parse(_CALC_HEAD + _CALC_DEF + textwrap.indent(body, "    "))
        except (RecursionError, MemoryError):
            pytest.skip(
                "this Python's parser refuses the input; the scanner's parse-level "
                "RecursionError is handled by the crash-containment batch"
            )
    assert _calc(tmp_path, body) == ["AAK-TAINT-002"]


def test_unrelated_elif_arms_between_the_check_and_the_call_do_not_exhaust_the_stack(tmp_path: Path) -> None:
    """1,500 arms that check nothing. The first version of this skip ran out of
    stack at about 400, which lost every taint finding in the run."""
    chain = "if extra == 'o0':\n    pass\n" + "\n".join(f"elif extra == 'o{i}':\n    pass" for i in range(1, 1_500))
    assert _calc(tmp_path, chain + "\nreturn eval(expression)") == ["AAK-TAINT-002"]
    assert _calc(tmp_path, _CHECK + chain + "\nreturn eval(expression)") == []


def test_a_long_elif_chain_of_checks_is_read_without_recursion(tmp_path: Path) -> None:
    """Each arm is a check whose `else` holds the next: 1,500 blocks deep, read
    from a work list, where recursion would give up and report the call."""
    arms = "\n".join(f"elif not set(extra) <= OPERATORS:\n    raise ValueError({i})" for i in range(1, 1_500))
    body = "if not set(expression) <= OPERATORS:\n    raise ValueError(0)\n" + arms + "\nreturn eval(expression)"
    assert _calc(tmp_path, body) == []


# The skip reads each function and file once, and remembers each module
# constant and pattern it has judged: the first version re-read a name's value
# at every reference, so four names each a chain of 100 references to the next
# (1,985 bytes) took 67 seconds. Each test runs a crafted file at two sizes,
# best of three, and allows the larger 40 times the smaller's CPU time for 10
# times the work, plus a fixed slack, under an absolute bound loose for CI.


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        run()
        best = min(best, time.process_time() - started)
    return best


def _grows_linearly(tmp_path: Path, source: Callable[[int], str], count: int) -> None:
    """`source(count)` and `source(10 * count)`, each under the 1 MB file cap."""
    small, large = tmp_path / "small", tmp_path / "large"
    for root, n in ((small, count), (large, 10 * count)):
        root.mkdir()
        text = source(n)
        assert len(text.encode()) < 1_000_000
        (root / "server.py").write_text(text)
    t_small, t_large = _seconds(lambda: scan(small)), _seconds(lambda: scan(large))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def _tool(body_lines: list[str], module: str = "") -> str:
    return _CALC_HEAD + module + _CALC_DEF + "".join(f"    {line}\n" for line in body_lines)


def test_the_reviewers_name_chain_scans_in_linear_time(tmp_path: Path) -> None:
    chain = "A = " + " + ".join(['"0"'] * 100) + "\n" + "".join(
        f"{name} = " + " + ".join([below] * 100) + "\n" for below, name in (("A", "B"), ("B", "C"), ("C", "D"))
    )
    check = ["if not all(c in D for c in expression):", "    raise ValueError(expression)"]
    _grows_linearly(tmp_path, lambda n: _tool(check * n + ["return eval(expression)"], chain), 100)


def test_a_long_pattern_checked_many_times_scans_in_linear_time(tmp_path: Path) -> None:
    check = ["if not re.fullmatch(r'[" + "0-9" * 300 + "]+', expression):", "    raise ValueError(expression)"]
    _grows_linearly(tmp_path, lambda n: _tool(check * n + ["return eval(expression)"]), 100)


def test_many_checks_and_calls_scan_in_linear_time(tmp_path: Path) -> None:
    unit = ["if not set(expression) <= OPERATORS:", "    raise ValueError(expression)", "eval(expression)"]
    _grows_linearly(tmp_path, lambda n: _tool(unit * n + ["return None"]), 500)


def test_a_long_elif_chain_scans_in_linear_time(tmp_path: Path) -> None:
    def source(n: int) -> str:
        arms = [f"elif not set(extra) <= OPERATORS:\n        raise ValueError({i})" for i in range(n)]
        return _tool(["if not set(expression) <= OPERATORS:", "    raise ValueError(expression)", *arms, "return eval(expression)"])

    _grows_linearly(tmp_path, source, 100)


def test_re_bound_by_something_other_than_its_import_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import re as regex\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\nre = regex.compile('x')\n\n\n"
        "@mcp.tool()\ndef calc(expression: str) -> object:\n"
        "    if not re.fullmatch(r'[0-9+*/() -]+', expression):\n        raise ValueError\n"
        "    return eval(expression)\n"
    )
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-002"]


def test_a_rebound_set_keeps_an_inline_set_check_reported(tmp_path: Path) -> None:
    body = "if not set(expression) <= {'1', '+'}:\n    raise ValueError\nreturn eval(expression)"
    assert _calc(tmp_path, body) == []
    assert _calc(tmp_path, body, "set = lambda value: frozenset()\n") == ["AAK-TAINT-002"]


@pytest.mark.parametrize("check", [
    "if not all(c in allowed for c in expression):",
    "if not set(expression) <= allowed:",
], ids=["all", "set"])
@pytest.mark.parametrize(("after", "reported"), [
    # Nothing else reads the local: the `all()` check reads it from its own
    # generator, the one nested read a local may have.
    ("", False),
    # Any other nested scope that reads it, even only to compare, after the
    # call so that nothing else about the call changes.
    ("def matches(c):\n    return c in allowed\n", True),
    ("matches = lambda c: c in allowed\n", True),
    ("class Box:\n    plus = '+' in allowed\n", True),
    ("flags = [c in allowed for c in more]\n", True),
    ("found = any(c in allowed for c in more)\n", True),
], ids=["no other reader", "a nested def", "a lambda", "a class body", "a list comprehension", "another generator"])
def test_a_local_allow_list_is_read_in_no_other_nested_scope(
    tmp_path: Path, check: str, after: str, reported: bool
) -> None:
    body = f"allowed = set('0123456789+-')\n{check}\n    raise ValueError\nresult = eval(expression)\n{after}return result"
    assert _calc(tmp_path, body) == (["AAK-TAINT-002"] if reported else [])
