"""Tree-sitter data-flow for AAK-MCP-STDIO-CMD-INJ-002 (#22).

The rule used to decide on proximity: a `new StdioClientTransport({...})` was
tainted if a network-controlled marker appeared anywhere in the preceding 1024
characters. That both over-fires (an unrelated source nearby) and under-fires (a
real source beyond the window).

What the rule reports is unchanged — same rule_id, severity, framework mappings.
Only the decision moved. These tests cover the two failure modes the old
heuristic had, the acceptance criteria in the issue, and the requirement that
the grammar stay optional.
"""

from __future__ import annotations

import builtins
import shutil
import sys
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.scanners import _ts_stdio_taint as taint
from agent_audit_kit.scanners.mcp_stdio_params import (
    _TS_STDIO_TRANSPORT_RE,
    _TS_TAINT_RE,
    scan,
)

RULE = "AAK-MCP-STDIO-CMD-INJ-002"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "ox-mcp-stdio-class"

_IMPORT = 'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";\n'


def _proximity_would_fire(text: str) -> bool:
    """The old heuristic, kept here to document what changed."""
    for m in _TS_STDIO_TRANSPORT_RE.finditer(text):
        if _TS_TAINT_RE.search(text[max(0, m.start() - 1024):m.start()]):
            return True
    return False


def _scan_source(tmp_path: Path, body: str, name: str = "server.ts") -> set[str]:
    (tmp_path / name).write_text(_IMPORT + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


requires_grammar = pytest.mark.skipif(
    not taint.available(), reason="tree-sitter TS grammar not installed"
)


@pytest.fixture
def without_grammar():
    """tree-sitter unimportable, as in a default install without the `taint` extra."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("tree_sitter"):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    saved = {m: sys.modules[m] for m in list(sys.modules) if m.startswith("tree_sitter")}
    try:
        builtins.__import__ = blocked
        for m in list(saved):
            sys.modules.pop(m, None)
        taint._load.cache_clear()
        yield
    finally:
        builtins.__import__ = real_import
        sys.modules.update(saved)
        taint._load.cache_clear()


# --- acceptance criteria from the issue -------------------------------------


@requires_grammar
def test_committed_vulnerable_fixture_fires() -> None:
    assert taint.find_tainted_sink((FIXTURES / "vulnerable_ts.ts").read_text()) is not None


@requires_grammar
def test_committed_patched_fixture_is_silent() -> None:
    assert taint.find_tainted_sink((FIXTURES / "patched_ts.ts").read_text()) is None


@requires_grammar
def test_unconnected_fixture_is_silent() -> None:
    """Source and sink both present, nothing flowing between them."""
    assert taint.find_tainted_sink((FIXTURES / "unconnected_ts.ts").read_text()) is None


def test_unconnected_fixture_is_the_case_proximity_got_wrong() -> None:
    """Documents why the fixture exists: the old heuristic fires on it."""
    src = (FIXTURES / "unconnected_ts.ts").read_text()
    assert _proximity_would_fire(src), "fixture no longer exercises the over-fire"


# --- the two failure modes --------------------------------------------------


@requires_grammar
def test_over_fire_is_fixed(tmp_path: Path) -> None:
    """An unrelated source next to a constant-fed sink must not fire."""
    body = (
        "export async function handler(req: any) {\n"
        "  const reason = req.body.reason;\n"
        "  await audit(reason);\n"
        '  return new StdioClientTransport({ command: "/usr/bin/server-a", args: [] });\n'
        "}\n"
    )
    assert RULE not in _scan_source(tmp_path, body)


@requires_grammar
def test_under_fire_is_fixed(tmp_path: Path) -> None:
    """A real source beyond the 1024-char window, reached via a helper."""
    body = (
        "function pickCommand(req: any) { return req.body.command; }\n"
        + "// an unrelated line of code\n" * 200
        + "export function handler(req: any) {\n"
        "  const cmd = pickCommand(req);\n"
        "  return new StdioClientTransport({ command: cmd, args: [] });\n"
        "}\n"
    )
    assert not _proximity_would_fire(_IMPORT + body), "source should be outside the old window"
    assert RULE in _scan_source(tmp_path, body)


# --- flow shapes the issue lists --------------------------------------------


@requires_grammar
@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("direct", "export function h(req: any) {\n"
                   "  return new StdioClientTransport({ command: req.body.command, args: [] });\n}\n"),
        ("assignment", "export function h(req: any) {\n"
                       "  const c = req.body.command;\n"
                       "  return new StdioClientTransport({ command: c, args: [] });\n}\n"),
        ("destructuring", "export function h(req: any) {\n"
                          "  const { command } = req.body;\n"
                          "  return new StdioClientTransport({ command, args: [] });\n}\n"),
        ("env", "export function h() {\n"
                "  const c = process.env.MCP_COMMAND;\n"
                "  return new StdioClientTransport({ command: c, args: [] });\n}\n"),
        ("json-parse", "export function h(raw: string) {\n"
                       "  const cfg = JSON.parse(raw);\n"
                       "  return new StdioClientTransport({ command: cfg.command, args: [] });\n}\n"),
        ("awaited-fetch", "export async function h(u: string) {\n"
                          "  const cfg = await fetch(u);\n"
                          "  return new StdioClientTransport({ command: cfg.command, args: [] });\n}\n"),
    ],
)
def test_tainted_flows_fire(label: str, body: str, tmp_path: Path) -> None:
    assert RULE in _scan_source(tmp_path, body), label


@requires_grammar
@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("constant", "export function h() {\n"
                     '  return new StdioClientTransport({ command: "/usr/bin/x", args: [] });\n}\n'),
        ("allowlist-table", "const OK: Record<string,string> = { a: \"/usr/bin/a\" };\n"
                            "export function h(name: string) {\n"
                            "  const c = OK[name];\n"
                            "  if (!c) throw new Error('no');\n"
                            "  return new StdioClientTransport({ command: c, args: [] });\n}\n"),
        ("no-sink", "export function h(req: any) {\n"
                    "  return req.body.command;\n}\n"),
    ],
)
def test_untainted_shapes_stay_silent(label: str, body: str, tmp_path: Path) -> None:
    assert RULE not in _scan_source(tmp_path, body), label


# --- the grammar must stay optional ----------------------------------------


def test_falls_back_to_proximity_when_the_grammar_is_absent(tmp_path: Path, without_grammar: None) -> None:
    """With tree-sitter unimportable, the proximity scan runs and no import
    error is raised."""
    assert taint.available() is False
    assert taint.find_tainted_sink(_IMPORT + "const x = 1;\n") is None

    work = tmp_path / "fb"
    work.mkdir()
    shutil.copy(FIXTURES / "vulnerable_ts.ts", work / "vulnerable_ts.ts")
    assert RULE in {f.rule_id for f in scan(work)[0]}

    clean = tmp_path / "fb2"
    clean.mkdir()
    shutil.copy(FIXTURES / "patched_ts.ts", clean / "patched_ts.ts")
    assert RULE not in {f.rule_id for f in scan(clean)[0]}


# --- the two paths agree where the fallback can see the flow ---------------
#
# The fallback read only the 1024 characters before `new StdioClientTransport(`,
# so the most direct shape, a source written in the transport's own `command`
# or `args`, was CRITICAL with tree-sitter and silent without it, and a plain
# `pip install` (no `taint` extra) is what most users run.

_INLINE = ("export function connect(req: any) {\n"
           "  return new StdioClientTransport({ command: req.body.command, args: req.body.args });\n}\n")

_BOTH_PATHS = [
    ("inline-request", _INLINE, True),
    ("express-handler", 'app.post("/connect", async (req, res) => {\n'
                        "  const transport = new StdioClientTransport({ command: req.body.command, args: req.body.args });\n"
                        "  await client.connect(transport);\n});\n", True),
    ("inline-env-arg", "export function h() {\n"
                       '  return new StdioClientTransport({ command: "npx", args: ["-y", process.env.MCP_PACKAGE] });\n}\n',
     True),
    ("inline-json-parse", "export function h(raw: string) {\n"
                          "  return new StdioClientTransport({ command: JSON.parse(raw).command, args: [] });\n}\n", True),
    ("inline-template", "export function h(req: any) {\n"
                        "  return new StdioClientTransport({ command: `${req.query.bin}`, args: [] });\n}\n", True),
    ("quoted-key", "export function h(req: any) {\n"
                   '  return new StdioClientTransport({ "command": req.params.cmd, "args": [] });\n}\n', True),
    ("multi-line", "export function h(req: any) {\n"
                   "  return new StdioClientTransport({\n"
                   '    command: "node",\n'
                   "    args: [\n      \"server.js\",\n      req.body.flag,\n    ],\n"
                   "  });\n}\n", True),
    ("env-block-only", "export function h() {\n"
                       '  return new StdioClientTransport({ command: "/usr/bin/server", args: ["--stdio"],\n'
                       "    env: { API_KEY: process.env.API_KEY } });\n}\n", False),
    ("constant", "export function h() {\n"
                 '  return new StdioClientTransport({ command: "/usr/bin/x", args: [] });\n}\n', False),
    ("source-after-the-call", "export function h() {\n"
                              '  return new StdioClientTransport({ command: "/usr/bin/x", args: [] });\n}\n'
                              "export function other(req: any) {\n"
                              "  const opts = { args: req.body.args };\n  return opts;\n}\n", False),
    # Comments in the options object. The fallback skipped strings but not
    # comments: a comment before the key hid the member, an apostrophe in one
    # opened a string that ran on, and a source named in one counted as a value.
    ("line-comment-above-key", "export function h(req: any) {\n"
                               "  return new StdioClientTransport({\n"
                               "    // the command comes from the request\n"
                               "    command: req.body.command,\n    args: [],\n  });\n}\n", True),
    ("block-comment-before-key", "export function h(req: any) {\n"
                                 "  return new StdioClientTransport({ /* user-supplied */ command: req.body.command });\n}\n",
     True),
    ("apostrophe-in-a-comment", "export function h(req: any) {\n"
                                "  return new StdioClientTransport({\n"
                                "    args: [], // don't hardcode the binary\n"
                                "    command: req.body.command,\n  });\n}\n", True),
    ("source-named-in-a-comment", "export function h() {\n"
                                  "  return new StdioClientTransport({\n"
                                  "    command: 'node' /* never from req.body */,\n"
                                  "    args: ['server.js'],\n  });\n}\n", False),
    ("commented-out-sink", "export function h(req: any) {\n"
                           "  // new StdioClientTransport(\n"
                           "  const opts = { command: req.body.command };\n  return opts;\n}\n", False),
    # The sources the data-flow path reads: Koa's `ctx`, any `process.env` name.
    ("koa-ctx-query", "export function h(ctx: any) {\n"
                      "  return new StdioClientTransport({ command: ctx.query.cmd, args: [] });\n}\n", True),
    ("lower-case-env-name", "export function h() {\n"
                            "  return new StdioClientTransport({ command: process.env.mcpCommand, args: [] });\n}\n",
     True),
    # A quote inside a regex literal opened a phantom string in the options
    # reader; a `/` after an operand is a division, not a regex.
    ("regex-literal-with-a-quote", "export function h(req: any, u: string) {\n"
                                   "  return new StdioClientTransport({ args: [u.replace(/'/g, '')], command: req.body.cmd });\n}\n",
     True),
    ("division-before-command", "export function h(req: any, a: number, b: number) {\n"
                                "  return new StdioClientTransport({ args: [String(a / b)], command: req.body.cmd });\n}\n",
     True),
    ("regex-literal-constant-command", "export function h(u: string) {\n"
                                       "  return new StdioClientTransport({ args: [u.replace(/\"/g, '')], command: 'node' });\n}\n",
     False),
    # After a postfix `++` or `--` a slash divides, as `blank_js_comments` reads it.
    ("postfix-increment-before-a-slash", "export function h(req: any, i: number) {\n"
                                         "  return new StdioClientTransport({ args: [String(i++ / 2), '/'], command: req.body.cmd });\n}\n",
     True),
    ("postfix-decrement-before-a-slash", "export function h(req: any, i: number) {\n"
                                         "  return new StdioClientTransport({ args: [String(i-- / 2), '/'], command: req.body.cmd });\n}\n",
     True),
]


@requires_grammar
@pytest.mark.parametrize(("label", "body", "fires"), _BOTH_PATHS, ids=[c[0] for c in _BOTH_PATHS])
def test_with_the_grammar(label: str, body: str, fires: bool, tmp_path: Path) -> None:
    assert (RULE in _scan_source(tmp_path, body)) is fires, label


@pytest.mark.parametrize(("label", "body", "fires"), _BOTH_PATHS, ids=[c[0] for c in _BOTH_PATHS])
def test_without_the_grammar(label: str, body: str, fires: bool, tmp_path: Path, without_grammar: None) -> None:
    assert (RULE in _scan_source(tmp_path, body)) is fires, label


def _long_first_member(n: int) -> str:
    """A transport whose `command` member closes `n + 37` characters into the call."""
    return ("export function h(ctx: any) {\n"
            f"  return new StdioClientTransport({{ args: ['{'x' * n}'], command: ctx.query.cmd }});\n}}\n")


def test_the_fallback_reads_the_first_1024_characters_of_the_call(tmp_path: Path, without_grammar: None) -> None:
    """The options reader stops 1,024 characters into the call, so a crafted
    file stays linear: a `command` member that closes later is not read, and
    the limitation says so."""
    from agent_audit_kit.rules.builtin import RULES

    inside, outside = tmp_path / "inside", tmp_path / "outside"
    inside.mkdir()
    outside.mkdir()
    assert RULE in _scan_source(inside, _long_first_member(986))  # closes at character 1,024
    assert RULE not in _scan_source(outside, _long_first_member(987))  # closes at 1,025
    assert "within the first 1,024 characters of the call" in RULES[RULE].limitations


def test_a_regex_after_a_block_brace_is_read_as_a_division(tmp_path: Path, without_grammar: None) -> None:
    """After a `}` the fallback reads a `/` as a division, as `blank_js_comments`
    does: a block's brace and an object's are the same token. A quote in such a
    regex then opens a string, which can hide the members after it, and the
    limitation says so. The string ends at its line's end, as a quoted string
    does, so a function body laid out over several lines loses nothing."""
    from agent_audit_kit.rules.builtin import RULES

    head = "export function h(req: any, a: boolean, s: string) {\n  return new StdioClientTransport({\n"
    tail = "    command: req.body.cmd, cwd: '/tmp' });\n}\n"
    one_line, laid_out = tmp_path / "one-line", tmp_path / "laid-out"
    one_line.mkdir()
    laid_out.mkdir()
    assert RULE not in _scan_source(one_line, head + "    args: [(() => { if (a) {} /'/.test(s); return ''; })()],\n" + tail)
    assert RULE in _scan_source(laid_out, head + "    args: [(() => {\n      if (a) {} /'/.test(s)\n"
                                          "      return []\n    })()],\n" + tail)
    assert "right after a block's closing brace" in RULES[RULE].limitations


def test_the_fallback_evidence_says_which_path_ran(tmp_path: Path, without_grammar: None) -> None:
    (tmp_path / "s.ts").write_text(_IMPORT + _INLINE, encoding="utf-8")
    found = [f for f in scan(tmp_path)[0] if f.rule_id == RULE]
    assert found and "[proximity heuristic" in found[0].evidence
    assert "command or args" in found[0].evidence


@requires_grammar
def test_the_data_flow_evidence_says_which_path_ran(tmp_path: Path) -> None:
    (tmp_path / "s.ts").write_text(_IMPORT + _INLINE, encoding="utf-8")
    found = [f for f in scan(tmp_path)[0] if f.rule_id == RULE]
    assert found and "data-flow analysis" in found[0].evidence
    assert "proximity" not in found[0].evidence


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


# Transports whose options never close, members full of brackets, and comments
# and strings that never close. Each shape runs at two sizes, best of three, and
# the larger may take 40 times the smaller's time for 10 times the text plus a
# fixed slack, under an absolute bound that is loose for slow CI runners.
_CRAFTED = {
    "unclosed-options": lambda k: "new StdioClientTransport({ command: (" * k,
    "bracket-members": lambda k: ("new StdioClientTransport({ command: [" + "(" * 50 + "\n") * (k // 3),
    "unclosed-comment": lambda k: "new StdioClientTransport({ /* " * k,
    "unclosed-string": lambda k: "new StdioClientTransport({ command: '" * k,
    "unclosed-regex": lambda k: "new StdioClientTransport({ args: [x, /'" * k,
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED))
def test_the_fallback_reads_a_crafted_file_in_linear_time(tmp_path: Path, shape: str, without_grammar: None) -> None:
    roots = []
    for name, k in (("small", 2_800), ("large", 28_000)):
        root = tmp_path / name
        root.mkdir()
        (root / "s.ts").write_text(_CRAFTED[shape](k), encoding="utf-8")
        roots.append(root)
    t_small, t_large = _seconds(lambda: scan(roots[0])), _seconds(lambda: scan(roots[1]))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_malformed_typescript_does_not_raise() -> None:
    assert taint.find_tainted_sink("export function ( {{{ unterminated") is None


@requires_grammar
def test_reported_rule_metadata_is_unchanged(tmp_path: Path) -> None:
    """This changed how the rule decides, not what it reports."""
    from agent_audit_kit.rules.builtin import RULES

    body = ("export function h(req: any) {\n"
            "  return new StdioClientTransport({ command: req.body.command, args: [] });\n}\n")
    (tmp_path / "s.ts").write_text(_IMPORT + body, encoding="utf-8")
    found = [f for f in scan(tmp_path)[0] if f.rule_id == RULE]
    assert found
    assert found[0].severity == RULES[RULE].severity
    assert found[0].category == RULES[RULE].category
