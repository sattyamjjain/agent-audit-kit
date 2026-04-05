from __future__ import annotations

from pathlib import Path

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
