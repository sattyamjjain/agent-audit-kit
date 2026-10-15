"""AAK-MCP-011's FastAPI route search keeps its matches and reads in linear time.

The route and the `def` it decorates were one DOTALL pattern. Every route
before the same `)` read to it, and `\\s*(?::|\\s*->)` split a run of blanks
every way: 40 KB of blanks after a `def` took 1.2 seconds and the time grew
with the square. `_first_fastapi_mcp_handler` reads each `)` once.
"""

from __future__ import annotations

import time

import pytest

from agent_audit_kit.scanners.mcp_auth_patterns import _first_fastapi_mcp_handler


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
