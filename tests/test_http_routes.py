"""The shared route reader, `_http_routes.CodeIndex`: what it treats as code.

The route rules (AAK-MCP-016, -019, -020 and AAK-MCPWN-001) read a call's
arguments through it, so a string, comment or regex literal it misreads hides
or invents the routes after it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import agent_audit_kit
from agent_audit_kit.scanners._http_routes import CodeIndex


def _args(text: str, call: str) -> list[str]:
    """The arguments of the last ``call`` (which ends at its `(`) in a TS/JS file."""
    index = CodeIndex(text)
    paren = text.rindex(call) + len(call) - 1
    assert index.in_code(paren), "the call was read as part of a string, comment or regex"
    return [text[s:e] for s, e in index.args(paren) or []]


ROUTE = "route('/mcp', handler);\n"
LATER = "const banner = `listening on ${port}`;\n"


@pytest.mark.parametrize("regex", [
    "/`/", '/"/g', "/'/", "/\\)/", "/[/)]/", "/[`'\"(]+/gi", "/a\\/b/", "/\\[/", "/[\\]/`]/",
])
def test_a_regex_literal_hides_what_it_holds(regex: str) -> None:
    text = f"const n = s.split({regex}).length;\n" + ROUTE + LATER
    assert _args(text, "route(") == ["'/mcp'", "handler"]


@pytest.mark.parametrize("before", [
    "x = ", "f(a, ", "[", "!", "a && ", "a || ", "c ? ", "c ? a : ", "{ ", "} ", "; ", "() => ", "\n",
    "return ", "typeof ", "case ", "k in ", "of ", "new ", "delete ", "void ", "throw ",
])
def test_a_regex_literal_is_read_where_an_expression_starts(before: str) -> None:
    text = f"{before}/`/;\n" + ROUTE + LATER
    assert _args(text, "route(") == ["'/mcp'", "handler"]


@pytest.mark.parametrize("expr", ["a / b", "a / b / c", "x[i] / 2", "f() / g()", "n / 2 / k", "a.b / c", "x /= 2"])
def test_division_stays_division(expr: str) -> None:
    """Read as a regex, the first `/` would run to the `/` inside `'/mcp'`."""
    text = f"const q = {expr}; " + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]


def test_a_division_broken_onto_the_next_line_stays_division() -> None:
    """A formatter puts the `/` of a long division first on the new line, and JS
    inserts no semicolon before it."""
    text = "const avg = total\n  / count; " + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]


def test_a_regex_literal_opening_the_file_is_read() -> None:
    text = "/`/.test(s);\n" + ROUTE + LATER
    assert _args(text, "route(") == ["'/mcp'", "handler"]


def test_comments_are_still_comments() -> None:
    text = "// route('/x', a);\n/* route('/y', b); */\n" + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]


def test_go_has_no_regex_literals() -> None:
    """In Go a `/` is division, whatever comes before it."""
    text = 'x := (a) / 2\nr.Handle("/mcp", h)\n'
    index = CodeIndex(text, go=True)
    paren = text.index("Handle(") + len("Handle")
    assert [text[s:e] for s, e in index.args(paren) or []] == ['"/mcp"', "h"]


def _seconds(text: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        CodeIndex(text)
        best = min(best, time.perf_counter() - started)
    return best


_CRAFTED = {
    # Each `/[` opens a class that never closes: every one read the same window.
    "unclosed classes": "(/[",
    "classes of escapes": "(/[\\",
    "escapes": "(/\\x",
    "regexes": "(/x/)",
    "slashes": "(/",
    "divisions": "a / ",
    "comments before a slash": "(/* c */ /x/)",
}


@pytest.mark.parametrize("unit", sorted(_CRAFTED))
def test_a_crafted_file_reads_in_linear_time(unit: str) -> None:
    """Ten times the input must not take a hundred times as long."""
    small, large = _CRAFTED[unit] * 12_000, _CRAFTED[unit] * 120_000
    t_small, t_large = _seconds(small), _seconds(large)
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


# A child process reads each crafted file, so a quadratic read fails the test on
# its timeout instead of stalling the suite.
_CHILD = (
    "import sys, time\n"
    "from agent_audit_kit.scanners._http_routes import CodeIndex\n"
    "text = open(sys.argv[1], encoding='utf-8').read()\n"
    "started = time.perf_counter()\n"
    "CodeIndex(text, go=sys.argv[2] == 'go')\n"
    "print(time.perf_counter() - started)\n"
)


def _seconds_in_child(tmp_path: Path, text: str, go: bool = False) -> float:
    source = tmp_path / "input.txt"
    source.write_text(text, encoding="utf-8")
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _CHILD, str(source), "go" if go else "js"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert done.returncode == 0, done.stderr
    return float(done.stdout)


# An opening quote that never closes, then escaped quotes of its kind: each
# escaped quote was taken for an opener in turn, and each read again to the end
# of the line (a string) or of the file (a template). At 120 KB each took about
# 36 seconds; a 511 KB template was still running after 900.
_UNCLOSED = {
    "template": ("app.post('/mcp', h)\n`" + "\\`" * 60_000 + "\n", False),
    "double-quoted": ('const s = "' + '\\"' * 60_000 + "\n", False),
    "single-quoted": ("const s = '" + "\\'" * 60_000 + "\n", False),
    "Go string": ('package main\nvar s = "' + '\\"' * 60_000 + "\n", True),
    "Go rune": ("package main\nvar s = '" + "\\'" * 60_000 + "\n", True),
}


@pytest.mark.parametrize("shape", sorted(_UNCLOSED))
def test_an_unclosed_literal_full_of_escaped_quotes_reads_in_linear_time(tmp_path: Path, shape: str) -> None:
    text, go = _UNCLOSED[shape]
    assert _seconds_in_child(tmp_path, text, go) < 5.0


@pytest.mark.parametrize("opener", ['"', "'", "`"])
def test_the_code_after_an_unclosed_literal_is_still_read(opener: str) -> None:
    """A literal that never closes is no literal: its quote is skipped, and so are
    the escaped quotes of its kind after it, which cannot close it either."""
    text = f"const s = {opener}no end \\{opener} here\\{opener}\n" + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]
