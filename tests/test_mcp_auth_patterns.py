"""AAK-MCP-011's FastAPI route search keeps its matches and reads in linear time.

The route and the `def` it decorates were one DOTALL pattern. Every route
before the same `)` read to it, and `\\s*(?::|\\s*->)` split a run of blanks
every way: 40 KB of blanks after a `def` took 1.2 seconds and the time grew
with the square. `_first_fastapi_mcp_handler` reads each `)` once.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners.mcp_auth_patterns import _first_fastapi_mcp_handler, scan


@pytest.mark.parametrize(("source", "span"), [
    ('@app.post("/mcp")\nasync def mcp(req):', (0, 37)),
    ('@app.get("/mcp/x", tags=["a"])\ndef h(a, b) -> dict:', (0, 45)),
    # The first route has no `def` after its `)`: the second one is the match.
    ('@app.post("/mcp")\nx = 1\n@app.post("/mcp2")\ndef h():', (24, 51)),
    ('@app.post("/api")\ndef h():', None),
])
def test_the_first_mcp_handler_keeps_its_span(source: str, span: tuple[int, int] | None) -> None:
    assert _first_fastapi_mcp_handler(source) == span


@pytest.mark.parametrize("source", [
    '@app.get("/mcp"' * 34_000,
    '@app.get("/mcp")def f()' + " " * 500_000,
])
def test_a_crafted_route_file_reads_in_linear_time(source: str) -> None:
    """About 500 KB, under the scanner's 512 KB cap. The bound is loose for
    slow CI runners."""
    started = time.perf_counter()
    _first_fastapi_mcp_handler(source)
    assert time.perf_counter() - started < 5.0


# A file whose only MCP marker is a `@tool` decorator was never read: the gate
# wrote `\b(...|@tool|...)\b`, and a word boundary before `@` needs a word
# character in front of it.
_CORS_WITH_CREDENTIALS = (
    "CORS = {\n"
    '    "Access-Control-Allow-Origin": "*",\n'
    '    "Access-Control-Allow-Credentials": "true",\n'
    "}\n"
)


@pytest.mark.parametrize(("decorator", "read"), [
    ("@tool", True),
    ("@tool()", True),
    ("@toolbox", False),
])
def test_a_tool_decorator_alone_marks_the_file(tmp_path: Path, decorator: str, read: bool) -> None:
    (tmp_path / "server.py").write_text(
        _CORS_WITH_CREDENTIALS + f"\n\n{decorator}\ndef read_note(note_id: str) -> str:\n    return note_id\n",
        encoding="utf-8",
    )
    assert ("AAK-MCP-013" in {f.rule_id for f in scan(tmp_path)[0]}) is read
