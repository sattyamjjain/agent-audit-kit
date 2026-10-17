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
    # A binary or unary operator, `export default`, and the `)` that closes a
    # statement's header: the reader took the `/` after these for division, so
    # a backtick in the literal opened a template that ran to the next backtick.
    "x = p + ", "x = p - ", "x = p * ", "x = p ** ", "x = p % ", "x = p < ", "x = p > ", "x = p >> ",
    "x = ~", "x = p ^ ", "x = -", "x = +", "export default ", "if (md) ", "} else if (md) ", "while (go) ",
    "for (;;) ", "with (o) ",
])
def test_a_regex_literal_is_read_where_an_expression_starts(before: str) -> None:
    text = f"{before}/`/;\n" + ROUTE + LATER
    assert _args(text, "route(") == ["'/mcp'", "handler"]


@pytest.mark.parametrize("expr", [
    "a / b", "a / b / c", "x[i] / 2", "f() / g()", "n / 2 / k", "a.b / c", "x /= 2",
    # `++` and `--` end an operand; a keyword after `.` is a property; an object
    # literal's `}` ends an expression, unlike a block's.
    "i++ / 2", "i-- / 2", "stats.in / 2", "range.of / 2", "o?.delete / 2", "({a: 1}).a / 2", "{a: 1} / 2",
    "f(x) / 2", "if_ / 2",
])
def test_division_stays_division(expr: str) -> None:
    """Read as a regex, the first `/` would run to the `/` inside `'/mcp'`."""
    text = f"const q = {expr}; " + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]


@pytest.mark.parametrize("markup", [
    "const v = <p>x</p>; ",
    "const v = <p>{a}/{b}</p>; ",
    "const v = <a href={u}/>; ",
])
def test_jsx_closing_tags_and_text_are_not_regex_literals(markup: str) -> None:
    """`</p>`, a self-closing `/>` and text between JSX containers: read as a
    regex, the `/` would run to the `/` inside `'/mcp'` on the same line."""
    text = markup + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]


@pytest.mark.parametrize("template", [
    # A backtick inside a string inside a substitution (a Markdown fence).
    "`${\"```\"}json`",
    "`${\"```\"}json\\n${body}\\n${\"```\"}`",
    # A template nested in a substitution, braces and a `}` in a string inside one.
    "`a ${`b ${c} d`} e`",
    "`${ {a: 1}.a } and ${f({x})}`",
    "`${\"}\"}`",
    # A regex literal holding a backtick inside a substitution.
    "`${s.split(/`/).length}`",
])
def test_a_template_substitution_is_read_as_code(template: str) -> None:
    """The reader took a template to run to the next backtick, so one inside a
    substitution ended it early and the stray backtick after it opened another
    that hid the code that followed."""
    text = f"const t = {template};\n" + ROUTE + LATER
    assert _args(text, "route(") == ["'/mcp'", "handler"]


def test_a_template_with_no_substitution_is_a_plain_string() -> None:
    text = "app.post(`/mcp`, h);\napp.post(`/mcp/${id}`, h);\napp.post(`/mcp\\${x}`, h);\n"
    index = CodeIndex(text)
    paths = []
    for line_start in (0, text.index("app.post(`/mcp/$"), text.index("app.post(`/mcp\\")):
        paren = text.index("(", line_start)
        start, end = (index.args(paren) or [])[0]
        paths.append(index.string_literal(start, end))
    assert paths == ["/mcp", None, None]


def test_code_in_a_substitution_is_code() -> None:
    text = "const t = `${route('/x', a)}`;\n"
    index = CodeIndex(text)
    paren = text.index("route(") + len("route")
    assert index.in_code(paren) and index.close.get(paren) == text.index(", a)") + len(", a")


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
    # Template substitutions, open, closed and holding templates, and the
    # contexts read back from a `/`, a `{` or a `(`.
    "nested substitutions": "`${",
    "closed substitutions": "`${}",
    "templates in substitutions": "`${`",
    "statement headers": "if (x) /a/; ",
    "object literals": "x = {a: 1} / 2; ",
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


# Each `/` after a `[` opens a regex literal, and here every class closes, so
# each `/` read the whole 512-character window: at 511 KB, 2 to 9 seconds
# against under 0.1 for the same text with no `/`.
_CLOSED_CLASSES = ("[/]", "[/]xx", "[/]xxx", "[(/]x")


@pytest.mark.parametrize("unit", _CLOSED_CLASSES)
def test_regex_literals_full_of_closed_classes_read_in_linear_time(tmp_path: Path, unit: str) -> None:
    text = "(/" + unit * (511_000 // len(unit)) + "\n"
    t_text = _seconds_in_child(tmp_path, text)
    t_plain = _seconds_in_child(tmp_path, text.replace("/", "x"))
    assert t_text < 5.0
    assert t_text < 8 * t_plain + 0.25, (t_plain, t_text)


def test_nested_substitutions_whose_template_never_closes_read_in_linear_time(tmp_path: Path) -> None:
    """Each `}` closing a substitution read the template's text after it, which
    never closes, to the end of the file: 32,000 nested `${` (128 KB) took about
    24 seconds, a 511 KB file 277 seconds of CPU."""
    text = "app.post('/mcp', requireAuth, h);\n" + "`${" * 32_000 + "x" + "}" * 32_000 + "\n"
    assert _seconds_in_child(tmp_path, text) < 5.0


# go_handlers on one long line of func literals, and on the same literals one per
# line, in a child process: it prints the seconds go_handlers took and how many
# handlers it found.
_GO_HANDLERS_CHILD = (
    "import sys, time\n"
    "from agent_audit_kit.scanners._http_routes import CodeIndex, go_handlers\n"
    "index = CodeIndex(open(sys.argv[1], encoding='utf-8').read(), go=True)\n"
    "started = time.perf_counter()\n"
    "found = len(go_handlers(index))\n"
    "print(time.perf_counter() - started, found)\n"
)


def _go_handlers_in_child(tmp_path: Path, text: str) -> tuple[float, int]:
    source = tmp_path / "input.go"
    source.write_text(text, encoding="utf-8")
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _GO_HANDLERS_CHILD, str(source)], capture_output=True, text=True, timeout=60, env=env,
    )
    assert done.returncode == 0, done.stderr
    seconds, found = done.stdout.split()
    return float(seconds), int(found)


@pytest.mark.parametrize(("unit", "k", "found"), [
    ("func(w http.ResponseWriter, r *http.Request){},", 84_000, 84_000),
    ("func(r *http.Request) T ", 10_700, 0),
], ids=["bodies", "no-bodies"])
def test_func_literals_on_one_line_find_their_bodies_in_linear_time(
    tmp_path: Path, unit: str, k: int, found: int,
) -> None:
    """Each func literal looked for the end of its line from where it stood: 84,000
    with bodies on one line (4 MB) took 8.6 seconds, against 0.6 one per line.
    Without bodies the walk from each one's `)` toward the line end, which skips
    bracketed groups and stops only at `{`, `,`, `;` or `=`, stepped past every
    literal after it: 10,700 on one line (256 KB) took 26 seconds, against 0.02
    one per line."""
    one_line = "package main\nvar hs = []interface{}{" + unit * k + "}\n"
    t_line, found_line = _go_handlers_in_child(tmp_path, one_line)
    t_lines, found_lines = _go_handlers_in_child(tmp_path, one_line.replace(unit, unit + "\n"))
    assert found_line == found_lines == found
    assert t_line < 5.0
    assert t_line < 4 * t_lines + 0.25, (t_lines, t_line)


@pytest.mark.parametrize("opener", ['"', "'", "`"])
def test_the_code_after_an_unclosed_literal_is_still_read(opener: str) -> None:
    """A literal that never closes is no literal: its quote is skipped, and so are
    the escaped quotes of its kind after it, which cannot close it either."""
    text = f"const s = {opener}no end \\{opener} here\\{opener}\n" + ROUTE
    assert _args(text, "route(") == ["'/mcp'", "handler"]


@pytest.mark.parametrize(("body", "regex"), [(509, True), (510, False)])
def test_a_regex_literal_must_close_within_512_characters(body: int, regex: bool) -> None:
    """Its closing `/` 511 characters after the opening one, or 512: past the
    window it is division, and the backtick in it opens a template that hides
    the route up to the next backtick."""
    text = "x = /`" + "a" * body + "/;\n" + ROUTE + LATER
    index = CodeIndex(text)
    assert index.in_code(text.index("route(")) is regex
