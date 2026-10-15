from __future__ import annotations

import sys
import textwrap
from pathlib import Path

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
