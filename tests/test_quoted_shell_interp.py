"""Tests for the quoted-shell-interpolation family (2026-08 wave).

Two advisories, both CVSS 3.1 8.4, both of which a rule that only fires on
*unquoted* interpolation would walk straight past:

  - CVE-2026-55157 / GHSA-49mq-fc6q-3h46 (npm @ooples/token-optimizer-mcp
    < 5.1.0): `getent passwd "${username}" || grep "^${username}:" /etc/passwd`
    through execAsync. Both sites are double-quoted. Double quotes do not stop
    $(...) or backticks, so the quoting buys nothing.
  - CVE-2026-55071 / GHSA-49m4-vp58-wgc9 (PyPI stata-mcp < 1.19.0): an
    unsanitized package name concatenated into a Stata command and handed over
    as an argv element. The list form stops shell metacharacters and does
    nothing about newline injection into Stata's own command language, which
    has a shell escape.

The negatives pin the two claims that make the rule safe to ship: `shlex.quote`
clears it, and a plain argv list with no interpreter flag clears it.
"""

from __future__ import annotations

import random
import re
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import quoted_shell_interp as qsi
from agent_audit_kit.scanners.quoted_shell_interp import INTERP_RULE, PROFILE_RULE, scan


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _ids(tmp_path: Path) -> list[str]:
    findings, _ = scan(tmp_path)
    return sorted(f.rule_id for f in findings)


def _interp(tmp_path: Path) -> list:
    findings, _ = scan(tmp_path)
    return [f for f in findings if f.rule_id == INTERP_RULE]


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_rules_are_registered() -> None:
    for rule_id in (INTERP_RULE, PROFILE_RULE):
        assert rule_id in RULES
        assert RULES[rule_id].severity.value == "high"
        assert "CVE-2026-55157" in RULES[rule_id].cve_references
        assert "CVE-2026-55071" in RULES[rule_id].cve_references
        assert RULES[rule_id].limitations

    assert RULES[INTERP_RULE].category.value == "taint-analysis"
    assert RULES[PROFILE_RULE].category.value == "mcp-config"


# --------------------------------------------------------------------------
# The quoting nuance — the whole point of the rule.
# --------------------------------------------------------------------------


def test_double_quoted_interpolation_is_flagged(tmp_path: Path) -> None:
    """CVE-2026-55157. The value is quoted; it is still command execution."""
    _write(tmp_path, "smart_user.ts", """
import { exec } from "child_process";
const execAsync = promisify(exec);

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const username = request.params.arguments.username as string;
  const { stdout } = await execAsync(
    `getent passwd "${username}" || grep "^${username}:" /etc/passwd`
  );
  return { content: [{ type: "text", text: stdout }] };
});
""")
    findings = _interp(tmp_path)
    assert len(findings) == 1, "one defect, not one per interpolation site"
    assert "inside double quotes" in findings[0].evidence
    assert "$(...)" in findings[0].evidence


def test_quoting_context_is_reported_distinctly(tmp_path: Path) -> None:
    """Bare, double-quoted and single-quoted sites get different explanations."""
    _write(tmp_path, "variants.py", """
import subprocess

@mcp.tool()
def bare(name: str) -> str:
    return subprocess.run(f"lookup {name}", shell=True, capture_output=True).stdout

@mcp.tool()
def double(name: str) -> str:
    return subprocess.run(f'lookup "{name}"', shell=True, capture_output=True).stdout

@mcp.tool()
def single(name: str) -> str:
    return subprocess.run(f"lookup '{name}'", shell=True, capture_output=True).stdout
""")
    evidence = {f.evidence.split("'")[1]: f.evidence for f in _interp(tmp_path)}
    assert "unquoted" in evidence["bare"]
    assert "do not stop" in evidence["double"]
    assert "literal '" in evidence["single"]


def test_argv_behind_an_eval_flag_is_flagged(tmp_path: Path) -> None:
    """CVE-2026-55071. An argv list is not a defence when an element is a program.

    `-b` precedes `-e` here, which is exactly the layout that defeats a scanner
    that stops at the first flag it recognises.
    """
    _write(tmp_path, "stata_tools.py", """
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("stata")

@mcp.tool()
def ado_package_install(package: str) -> str:
    cmd = 'ssc install "%s", replace' % package
    return subprocess.run(
        ["stata-mp", "-b", "-e", cmd], capture_output=True
    ).stdout.decode()
""")
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "interpreter eval flag" in findings[0].evidence
    assert "package" in findings[0].evidence


def test_taint_propagates_one_hop_through_a_local(tmp_path: Path) -> None:
    """The command is built into a local first — as every real advisory does.

    AAK-TAINT-001 only matches a bare parameter handed straight to the sink,
    which is why it saw neither CVE.
    """
    _write(tmp_path, "tools.py", """
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    command = "ping -c 1 " + host
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
""")
    assert INTERP_RULE in _ids(tmp_path)


# --------------------------------------------------------------------------
# True negatives.
# --------------------------------------------------------------------------


def test_shlex_quote_clears_the_finding(tmp_path: Path) -> None:
    _write(tmp_path, "safe.py", """
import shlex
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    command = "ping -c 1 " + shlex.quote(host)
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
""")
    assert _ids(tmp_path) == []


def test_plain_argv_list_is_not_flagged(tmp_path: Path) -> None:
    """No shell, no interpreter flag, no finding. This is the correct fix."""
    _write(tmp_path, "safe.py", """
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    return subprocess.run(
        ["ping", "-c", "1", host], capture_output=True
    ).stdout.decode()
""")
    assert _ids(tmp_path) == []


def test_constant_command_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "safe.py", """
import subprocess

@mcp.tool()
def uptime(unused: str) -> str:
    return subprocess.run("uptime", shell=True, capture_output=True).stdout.decode()
""")
    assert _ids(tmp_path) == []


def test_execfile_with_plain_argv_is_not_flagged(tmp_path: Path) -> None:
    """execFile does not spawn a shell, and no element here is a program."""
    _write(tmp_path, "safe.ts", """
import { execFile } from "child_process";

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const host = request.params.arguments.host as string;
  return execFile("ping", ["-c", "1", host]);
});
""")
    assert _ids(tmp_path) == []


def test_non_tool_function_is_not_flagged(tmp_path: Path) -> None:
    """An internal helper is not an agent-reachable surface."""
    _write(tmp_path, "internal.py", """
import subprocess

def rebuild(target: str) -> str:
    return subprocess.run(f"make {target}", shell=True, capture_output=True).stdout
""")
    assert _ids(tmp_path) == []


# --------------------------------------------------------------------------
# Default-profile reachability.
# --------------------------------------------------------------------------


def test_default_profile_fires_alongside_the_interp_finding(tmp_path: Path) -> None:
    _write(tmp_path, "tools.py", """
import subprocess

@mcp.tool()
def probe(host: str) -> str:
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout
""")
    assert _ids(tmp_path) == sorted([INTERP_RULE, PROFILE_RULE])


def test_env_gated_tool_clears_the_profile_rule(tmp_path: Path) -> None:
    """An opt-in gate is the remediation, so it has to clear the rule."""
    _write(tmp_path, "tools.py", """
import os
import subprocess

if os.environ.get("AAK_ENABLE_SHELL_TOOLS") == "1":

    @mcp.tool()
    def probe(host: str) -> str:
        return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout
""")
    ids = _ids(tmp_path)
    assert INTERP_RULE in ids, "the injection is still real"
    assert PROFILE_RULE not in ids, "but it is no longer reachable by default"


def test_profile_rule_does_not_fire_without_an_injection(tmp_path: Path) -> None:
    """It qualifies a real finding; it is not a complaint about running commands."""
    _write(tmp_path, "safe.py", """
import subprocess

@mcp.tool()
def uptime(unused: str) -> str:
    return subprocess.run(["uptime"], capture_output=True).stdout.decode()
""")
    assert PROFILE_RULE not in _ids(tmp_path)


# --------------------------------------------------------------------------
# Linear time.
# --------------------------------------------------------------------------

_HANDLER = """
import {{ exec }} from "child_process";

server.setRequestHandler(CallToolRequestSchema, async (request) => {{
  const username = request.params.arguments.username as string;
  exec(`{command}`);
}});
"""


def test_unclosed_interpolations_after_the_last_brace_add_nothing(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", _HANDLER.format(command='id "${username}" ${host ${port'))
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "parameter 'username'" in findings[0].evidence


def test_a_template_with_no_closing_brace_has_no_interpolation(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", _HANDLER.format(command="id ${username"))
    assert _interp(tmp_path) == []


def test_a_template_of_unclosed_interpolations_scans_in_linear_time(tmp_path: Path) -> None:
    """300 KB of `${` that never closes, after one that does. `[^}]*` read from
    each to the end of the template: 40,000 characters took 1.5 seconds, and
    the time grew with the square of the template. The bound is loose for slow
    CI runners; the scan takes milliseconds."""
    _write(tmp_path, "tool.ts", _HANDLER.format(command='id "${username}" ' + "${" * 150_000))
    started = time.perf_counter()
    findings = _interp(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert len(findings) == 1


_TYPED_LOCAL = """import { exec } from "child_process";

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const host = request.params.arguments.host as string;
  const cmd: Array<string> | string = `ping -c 1 ${host}`;
  exec(cmd);
});
"""


def test_a_typed_local_template_is_followed(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", _TYPED_LOCAL)
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "parameter 'host'" in findings[0].evidence


@pytest.mark.parametrize("typed", [True, False], ids=["typed", "untyped"])
def test_a_local_template_is_followed_in_a_file_that_starts_with_a_newline(
    tmp_path: Path, typed: bool
) -> None:
    """The look-back for the local's assignment walks up to sixty lines. When it
    reached the newline at offset 0 it asked for the last newline before offset
    -1, which counts from the end of the file, so the window jumped past the
    sink and the template was lost whenever a file's first line was blank."""
    source = _TYPED_LOCAL if typed else _TYPED_LOCAL.replace("const cmd: Array<string> | string = ", "const cmd = ")
    _write(tmp_path, "tool.ts", "\n" + source)
    findings = _interp(tmp_path)
    assert len(findings) == 1
    assert "parameter 'host'" in findings[0].evidence


def test_a_long_blank_type_scans_in_linear_time(tmp_path: Path) -> None:
    """300 KB of blanks after `cmd :` and no type. The type's class and the
    `\\s*` around it split the run every way: 2,000 blanks took 2.1 seconds and
    the time grew with the cube of the run. The bound is loose for slow CI
    runners; the scan takes milliseconds."""
    crafted = _TYPED_LOCAL.replace("const cmd:", "let cmd :" + " " * 300_000 + "\t\nconst cmd:")
    _write(tmp_path, "tool.ts", crafted)
    started = time.perf_counter()
    findings = _interp(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert len(findings) == 1


# --------------------------------------------------------------------------
# One pass per file.
# --------------------------------------------------------------------------
#
# Both passes read a file again for every place they looked at: the Python
# pass split the whole source into lines for every tool function, and the
# TS/JS passes read the template, its quoting, sixty lines back for a local,
# and the prefix for the line number at every sink, and the cross-file hop ran
# the header pattern from the top of the file to every sink and worked out the
# handler's tool-derived names and call arguments for every question. Each test
# below runs a crafted project at two sizes, best of three, and allows the
# larger 40 times the smaller's time for 10 times the text (the old passes
# needed 100 times or more) plus a fixed slack, under an absolute bound that is
# loose for slow CI runners.


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


# shape -> (project for k units, k for the smaller size)
_PYTHON_SHAPES: dict[str, tuple[Callable[[int], dict[str, str]], int]] = {
    # `ast.get_source_segment` split the file into lines for every tool
    # function: 227 KB of them took 7.6 seconds.
    "python-tool-functions": (
        lambda k: {"tools.py": "".join(f"@mcp.tool()\ndef f{i}(name: str) -> str:\n    return name\n" for i in range(k))},
        200,
    ),
}


_SINK_SHAPES: dict[str, tuple[Callable[[int], dict[str, str]], int]] = {
    # A sink read sixty lines back, which one long line makes the whole file:
    # 40 KB of `exec(cmd);` took a second.
    "sinks-on-one-line": (lambda k: {"tool.js": "const cmd = `ls ${args.path}`;\n" + "exec(cmd);" * k}, 1_000),
    # Each interpolation searched the template for its quoting, and each
    # finding split the whole template for its snippet.
    "distinct-interpolations": (
        lambda k: {"tool.js": "const x = args.p;\nexec(`" + "".join("${a%d}" % i for i in range(k)) + "`);\n"},
        300,
    ),
}


_SINK_LIB = "function run(name) {\n  exec(`ls ${name}`);\n}\n"
_CALLER = "const v = args.path;\nx = run(v);\n"


def _backward_chain(k: int) -> dict[str, str]:
    lines = [f"const x{i} = x{i - 1};\n" for i in range(k, 0, -1)]
    return {"lib.js": _SINK_LIB, "tool.js": "".join(lines) + f"const x0 = args.path;\ny = run(x{k});\n"}


_CROSS_FILE_SHAPES: dict[str, tuple[Callable[[int], dict[str, str]], int]] = {
    # The header pattern began at every character of a word and read it to its
    # end, from the top of the file for every sink: 16 KB took 2.8 seconds.
    "word-before-paren": (lambda k: {"lib.js": "a" * k + "(\n" + _SINK_LIB, "tool.js": _CALLER}, 4_000),
    "sinks-in-one-function": (
        lambda k: {"lib.js": "function run(name) {\n" + "  exec(`ls ${name}`);\n" * k + "}\n", "tool.js": _CALLER},
        200,
    ),
    # Each sink walked back over every closed function that takes the name.
    "closed-functions-first": (
        lambda k: {"lib.js": "function f(name) { }\n" * k + _SINK_LIB.replace("\n}", "\n" + "  exec(`ls ${name}`);\n" * k + "}"),
                   "tool.js": _CALLER},
        150,
    ),
    "untyped-return-types": (lambda k: {"lib.js": "f(): " * k + ";\n" + _SINK_LIB, "tool.js": _CALLER}, 1_000),
    "blanks-after-a-header": (lambda k: {"lib.js": "f()" + " " * k + "x\n" + _SINK_LIB, "tool.js": _CALLER}, 4_000),
    # Each pass of the fixed point found one more name: 8 KB took 6.3 seconds.
    "locals-listed-backwards": (_backward_chain, 300),
    "typed-declarations": (lambda k: {"lib.js": _SINK_LIB, "tool.js": "const a: " * k + "\n" + _CALLER}, 1_000),
    "destructuring-openers": (lambda k: {"lib.js": _SINK_LIB, "tool.js": "const {" * k + "}\n" + _CALLER}, 1_000),
    "nested-subscripts": (
        lambda k: {"lib.js": _SINK_LIB, "tool.js": "const a = " + "[" * k + "v" + "]" * k + ";\nx = run(a);\n" + _CALLER},
        2_000,
    ),
    # Every call's arguments were read to its closing paren, so nested calls
    # read theirs once per level: 20 KB of nested `run(` took 4.2 seconds.
    "nested-calls": (lambda k: {"lib.js": _SINK_LIB, "tool.js": _CALLER + "x = " + "run(" * k + "w" + ")" * k + ";\n"}, 2_000),
    "nested-calls-in-brackets": (
        lambda k: {"lib.js": _SINK_LIB, "tool.js": _CALLER + "x = " + "run([" * k + "w" + "])" * k + ";\n"},
        1_500,
    ),
    "nested-calls-unmatched-brackets": (
        lambda k: {"lib.js": _SINK_LIB, "tool.js": _CALLER + "x = " + "run([" * k + "w" + ")" * k + ";\n"},
        1_500,
    ),
    # The chains below come before the tainted call, so the lookup reads every
    # level. Each level's `)` sits in a `[)]` pair that the level around it
    # cuts, so no level read as a piece of the one around it and each was read
    # whole: 70 KB took 21 seconds.
    "nested-calls-straddling-brackets": (
        lambda k: {"lib.js": _SINK_LIB, "tool.js": "x = " + "run(" * k + "w" + "[)]" * k + ";\n" + _CALLER},
        2_000,
    ),
    # The same, inside brackets every level shares: 45 KB took 8 seconds.
    "nested-calls-in-shared-brackets": (
        lambda k: {
            "lib.js": _SINK_LIB,
            "tool.js": "x = " + "run(" * k + "[" * k + "w" + "[)]" * k + "]" * k + ";\n" + _CALLER,
        },
        1_000,
    ),
    # A `]` closes each call's `(` as a group, so splitting the arguments left
    # the rest of the chain at depth zero for every level: 60 KB took 10.5
    # seconds.
    "nested-calls-closed-by-brackets": (
        lambda k: {"lib.js": _SINK_LIB, "tool.js": "x = " + "run(]" * k + ")" * k + ";\n" + _CALLER},
        2_000,
    ),
}


_CRAFTED = {**_PYTHON_SHAPES, **_SINK_SHAPES, **_CROSS_FILE_SHAPES}


@pytest.mark.parametrize("shape", sorted(_CRAFTED))
def test_a_crafted_project_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    build, count = _CRAFTED[shape]
    roots = []
    for name, k in (("small", count), ("large", 10 * count)):
        root = tmp_path / name
        root.mkdir()
        for rel, text in build(k).items():
            assert len(text) < 400_000, "under the scanner's file cap"
            (root / rel).write_text(text, encoding="utf-8")
        roots.append(root)
    t_small, t_large = _seconds(lambda: scan(roots[0])), _seconds(lambda: scan(roots[1]))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_crafted_projects_still_report_their_findings(tmp_path: Path) -> None:
    """The timing shapes are not empty: the ones with a reachable sink report it."""
    for rel, text in _CRAFTED["sinks-on-one-line"][0](3).items():
        _write(tmp_path, rel, text)
    assert len(_interp(tmp_path)) == 3
    chain = tmp_path / "chain"
    chain.mkdir()
    for rel, text in _backward_chain(40).items():
        (chain / rel).write_text(text, encoding="utf-8")
    findings = [f for f in scan(chain)[0] if f.rule_id == INTERP_RULE]
    assert [(f.file_path, f.line_number) for f in findings] == [("lib.js", 2)]
    assert "tool.js:42 passes it to run()" in findings[0].evidence
    straddling = tmp_path / "straddling"
    straddling.mkdir()
    for rel, text in _CROSS_FILE_SHAPES["nested-calls-straddling-brackets"][0](40).items():
        (straddling / rel).write_text(text, encoding="utf-8")
    findings = [f for f in scan(straddling)[0] if f.rule_id == INTERP_RULE]
    assert [(f.file_path, f.line_number) for f in findings] == [("lib.js", 2)]
    assert "tool.js:3 passes it to run()" in findings[0].evidence


def test_an_argument_cut_short_inside_a_pair_keeps_what_the_pair_holds(tmp_path: Path) -> None:
    """The outer call's argument holds all of `[v)]` and strips it, so it reads
    clean; the inner call's ends at the `)` inside the pair, so its strip keeps
    `[v` and the tool value. The inner call is the one reported."""
    _write(tmp_path, "lib.js", _SINK_LIB)
    _write(tmp_path, "tool.js", "const v = args.path;\nx = run(\n  y = run(w[v)]);\n")
    findings = _interp(tmp_path)
    assert [(f.file_path, f.line_number) for f in findings] == [("lib.js", 2)]
    assert "tool.js:3 passes it to run()" in findings[0].evidence


def test_a_sink_inside_a_methods_object_literal_return_type_is_owned_by_the_method(tmp_path: Path) -> None:
    """The header pattern used to stop at each sink, so a method whose return
    type is an object literal holding the sink ended at that literal's `{`,
    and the literal counted as the method's body. Read once for the whole
    file, the header runs on to the real body; the owner keeps the old answer."""
    _write(tmp_path, "lib.ts", "const cmd = `ls ${name}`;\nclass A {\n  foo(name): {exec(cmd)} {\n  }\n}\n")
    _write(tmp_path, "tool.ts", "const v = args.path;\nx = obj.foo(v);\n")
    findings = _interp(tmp_path)
    assert [(f.file_path, f.line_number) for f in findings] == [("lib.ts", 3)]
    assert "tool.ts:2 passes it to foo()" in findings[0].evidence


# The per-sink code the file indexes replaced, kept as the oracle they must
# agree with on generated sources.


def _old_enclosing_param(text: str, pos: int, name: str) -> tuple[str, int] | None:
    for m in reversed(list(qsi._JS_HEADER_RE.finditer(text, 0, pos))):
        func = m.group("fname") or m.group("mname") or m.group("aname") or ""
        if func in qsi._JS_KEYWORDS:
            continue
        body = text.find("{", m.end())
        if body < 0 or body >= pos:
            continue
        segment = text[body + 1 : pos]
        if 1 + segment.count("{") - segment.count("}") <= 0:
            continue
        params = qsi._js_param_names(m.group("fparams") or m.group("mparams") or m.group("aparams") or "")
        if name in params and func:
            return func, params.index(name)
    return None


def _old_strip_subscripts(expr: str) -> str:
    prev = None
    while prev != expr:
        prev = expr
        expr = re.sub(r"\[[^\[\]]*\]", "", expr)
    return expr


def _old_is_tool_derived(expr: str, tainted: set[str], destructure: bool = False) -> bool:
    bare = _old_strip_subscripts(expr)
    if qsi._JS_TOOL_ARG_RE.search(bare):
        return True
    if destructure and re.search(r"\b(?:args|arguments|input)\b", bare):
        return True
    return any(re.search(rf"(?<![\w$.]){re.escape(n)}(?![\w$])", bare) for n in tainted)


def _old_tool_derived_names(text: str) -> set[str]:
    assigns: list[tuple[list[str], str]] = []
    for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])\s*([^;\n]+)", text):
        assigns.append(([m.group(1)], m.group(2)))
    for m in re.finditer(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=;\n]+)?=\s*([^;\n]+)", text):
        bound = []
        for part in qsi._split_top_level(m.group(1)):
            local = part.split(":")[-1].split("=")[0].strip().lstrip(".")
            if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                bound.append(local)
        assigns.append((bound, m.group(2)))
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for names, rhs in assigns:
            if set(names) <= tainted:
                continue
            if _old_is_tool_derived(rhs, tainted, destructure=len(names) > 1 or rhs.strip() in {"args", "input"}):
                tainted.update(names)
                changed = True
    return tainted


def _old_tool_arg_call(text: str, func: str, index: int) -> int | None:
    tainted = _old_tool_derived_names(text)
    for m in re.finditer(rf"(?<![\w$]){re.escape(func)}\s*\(", text):
        head = text[text.rfind("\n", 0, m.start()) + 1 : m.start()]
        if re.search(r"\bfunction\s*$|^\s*(?:(?:public|private|protected|static|async)\s+)*$", head):
            continue
        depth, args = 0, []
        for i in range(m.end() - 1, len(text)):
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            if depth == 0:
                args = qsi._split_top_level(text[m.end() : i], brackets="([{")
                break
        if index < len(args) and _old_is_tool_derived(args[index], tainted):
            return text[: m.start()].count("\n") + 1
    return None


_LIB_FRAGMENTS = [
    "function f(a, name) {", "function* g(x){", "$function k(name) {", "a$function m(name){", "functionexec(name) {",
    "function exec(cmd) {", "foo(name) {", "foo(name): T {", "foo(name): {a: 1} {", "foo(name): {exec(cmd)} {",
    "foo(name): exec(cmd) {x} {", "(name) => {", "(name): T => {", "(a): exec(cmd) => {", "x = async (name) => {",
    "xasync(name) => {", "if (x) {", "}", "{", "exec(`ls ${name}`);", "exec(cmd);", "const cmd = `x ${name}`;",
    "cmd = `z '${name}'`;", "execSync(`a ${b.name} \"${name}\"`)", "spawn('sh', ['-c', `${name}`])", "\n", "\n\n", ";",
    "`", "foo({name}) {", "foo(...name) {", "f(a)b(name) {", "(", ")", "=>", "=",
]
_HANDLER_FRAGMENTS = [
    "const v = args.path;", "const {a, b} = args;", "let w = v + 1;", "const z = obj[args.k];", "const t: string = v;",
    "run(v);", "x = run(x, v);", "x = run(run(v));", "x = run([run(v)]);", "x = obj.run(v, 2)", "function run(name) {",
    "public run(v)", "x = run(\n", "x = run(args.x)", "x = run(a, [b, v])", "x = run(v]", "x = run([v)", "x = run(a}, v)",
    "x = run((v))", "x = run(v[0])", "\n", ";", "const a: X = = v;", "const c =\n", "let {x: y, ...rest} = input;",
]


def _generated(rng: random.Random, fragments: list[str], most: int) -> str:
    return "".join(rng.choice(fragments) + rng.choice(["", " ", "\n"]) for _ in range(rng.randint(1, most)))


def test_the_file_indexes_agree_with_the_per_sink_code_they_replace() -> None:
    rng = random.Random(11)
    sink_at = re.compile(r"\b(?:execAsync|execSync|exec|spawnSync|spawn|execFile|execFileSync)\s*\(")
    for _ in range(300):
        lib = _generated(rng, _LIB_FRAGMENTS, 24)
        regex = [
            (m.start(), m.end(), m.group("fname") or m.group("mname") or m.group("aname") or "",
             m.group("fparams") or m.group("mparams") or m.group("aparams") or "")
            for m in qsi._JS_HEADER_RE.finditer(lib)
        ]
        assert [(h.start, h.end, h.func, h.params) for h in qsi._js_headers(lib)] == regex, lib
        owners = qsi._JsOwners(lib)
        for m in sink_at.finditer(lib):
            for name in ("name", "cmd", "a", "x"):
                assert owners.owner(m.start(), name) == _old_enclosing_param(lib, m.start(), name), (lib, m.start(), name)
        handler = _generated(rng, _HANDLER_FRAGMENTS, 20)
        assert qsi._js_tool_derived_names(handler) == _old_tool_derived_names(handler), handler
        reader = qsi._JsHandler(handler)
        for index in (0, 1):
            assert reader.tool_arg_call("run", index) == _old_tool_arg_call(handler, "run", index), (handler, index)
        brackets = "".join(rng.choice("[]a ,()") for _ in range(rng.randint(0, 24)))
        assert qsi._strip_subscripts(brackets) == _old_strip_subscripts(brackets), brackets


_CHAIN_OPENERS = ["run(", "run([", "run(]", "run( ", "run(v,", "run(args.", "run(a", "[run("]
_CHAIN_MIDDLES = ["w", "v", "args", "args ", "", "[", "]", "args.p", "input.", "a[v]", "params.arguments"]
_CHAIN_CLOSERS = ["[)]", ")]", ")", "])", "[)", ")]]", "[[)]]", "a[)]", "[)]v", ",v)", ", w)", "[v)]", "[ args)]"]
_SPAN_TAINTED = {"v", "w", "a", "args", "run", "ab", "vw"}


def _straddling_chain(rng: random.Random) -> str:
    """Calls nested up to ten deep, their closing parens in brackets."""
    depth = rng.randint(1, 10)
    return (
        rng.choice(["", "const v = args.path;\n"])
        + "x = "
        + "".join(rng.choice(_CHAIN_OPENERS) for _ in range(depth))
        + rng.choice(_CHAIN_MIDDLES)
        + "".join(rng.choice(_CHAIN_CLOSERS) for _ in range(depth))
        + rng.choice(["", ";\nx = run(v);\n"])
    )


def test_straddling_chains_agree_with_the_per_sink_code() -> None:
    """The call lookup against the code it replaced on nested chains whose
    brackets straddle the arguments, and the stripped-argument reader against
    stripping and searching the span itself, on spans of generated sources."""
    rng = random.Random(23)
    for _ in range(400):
        handler = _straddling_chain(rng)
        reader = qsi._JsHandler(handler)
        for index in (0, 1):
            assert reader.tool_arg_call("run", index) == _old_tool_arg_call(handler, "run", index), (handler, index)
    for _ in range(150):
        text = _generated(rng, _HANDLER_FRAGMENTS + _CHAIN_OPENERS + _CHAIN_CLOSERS, 8)
        reader = qsi._JsHandler(text)
        reader._index()
        bare = qsi._BareSpans(text, _SPAN_TAINTED, reader._bracket_close)
        for _ in range(40):
            a = rng.randrange(len(text))
            b = rng.randrange(a + 1, len(text) + 1)
            want = qsi._js_derived(_old_strip_subscripts(text[a:b]), _SPAN_TAINTED)
            assert bare.derived(a, b) == want, (text, a, b)


@pytest.mark.parametrize("imports", [
    "import subprocess",
    "from subprocess import run",
    "from subprocess import run as sh",
    "import subprocess as sp",
])
def test_an_imported_shell_sink_is_read_through_the_import(tmp_path: Path, imports: str) -> None:
    """`run(...)` after `from subprocess import run` is `subprocess.run`, as AAK-TAINT-001 reads it."""
    call = {"import subprocess": "subprocess.run", "from subprocess import run": "run",
            "from subprocess import run as sh": "sh", "import subprocess as sp": "sp.run"}[imports]
    _write(tmp_path, "server.py", (
        f"{imports}\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        f"@mcp.tool()\ndef listing(path: str) -> int:\n    return {call}(f\"ls {{path}}\", shell=True).returncode\n"
    ))
    assert [f.rule_id for f in _interp(tmp_path)] == [INTERP_RULE]


def test_a_star_import_leaves_a_bare_shell_name_unread(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", (
        "from subprocess import run\nfrom helpers import *\nfrom mcp.server.fastmcp import FastMCP\n\n"
        "mcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef listing(path: str) -> int:\n    return run(f\"ls {path}\", shell=True).returncode\n"
    ))
    assert _ids(tmp_path) == []
    assert _interp(tmp_path) == []
