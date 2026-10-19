"""Quoted shell interpolation + default-profile reachability — CWE-78 / CWE-94.

``AAK-TAINT-001`` already says "tool parameter flows to shell command", but it
only matches a **bare parameter passed straight to the sink**
(``subprocess.run(package)``). No real advisory looks like that. Every one of
them builds a command string first, and the string is where the interesting part
lives:

**Double quotes are not a mitigation.** In ``sh``/``bash``, ``$(...)``,
backticks and ``${...}`` all expand *inside* double quotes. A rule that only
fires on unquoted interpolation reads ``"${username}"`` as handled and says
nothing.

Two August 2026 advisories, both CVSS 3.1 **8.4**
(``AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``), both quoted:

  - **CVE-2026-55157** / GHSA-49mq-fc6q-3h46 — npm ``@ooples/token-optimizer-mcp``
    < 5.1.0. ``get-user-info`` interpolates a caller-controlled username into
    ``getent passwd "${username}" || grep "^${username}:" /etc/passwd`` and runs
    it through ``execAsync``. Both interpolation sites are double-quoted; both
    are wide open to ``$(...)``.
  - **CVE-2026-55071** / GHSA-49m4-vp58-wgc9 — PyPI ``stata-mcp`` < 1.19.0.
    ``ado_package_install`` concatenates an unsanitized ``package`` into a Stata
    command. The command is handed over as an **argv element**, so "we use a
    list, not a shell" holds — right up until you notice the element sits behind
    ``-e``, and Stata has its own shell escape. Newline injection into an
    interpreter's own command language reaches the OS just the same.

Hence two rules:

``AAK-SHELL-QUOTED-INTERP-001`` (high, taint-analysis)
    An agent/tool parameter reaches a shell-executing sink through an
    interpolated command string, including through a local variable and
    including when the interpolation site is quoted. Also fires on the
    argv-behind-an-eval-flag form (``["stata", "-e", cmd]``, ``["bash", "-c", cmd]``),
    because an argv list only helps when no element is itself a program.
    Suppressed by ``shlex.quote`` / ``shlex.join`` / ``shell-quote`` /
    ``execFile`` with a plain argv.

``AAK-SHELL-DEFAULT-PROFILE-001`` (high, mcp-config)
    The command-executing tool above is exposed in the server's **default** tool
    profile — no opt-in flag, env gate, or profile membership required. This is
    the condition that took both CVEs from "reachable if you turned on the risky
    profile" to "reachable out of the box", and it is the difference the CVSS
    ``PR:N`` reflects. Fires only for tools that already reach a command sink,
    so it is a qualifier on a real finding rather than a standalone complaint
    about servers that happen to run commands.
"""

from __future__ import annotations

import ast
import math
import re
from bisect import bisect_left, bisect_right
from functools import lru_cache
from pathlib import Path
from typing import Callable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    PySource as _PySource,
    in_skip_dir,
    make_finding,
    parse_python,
    refusing_overflow,
    walk_tree,
)
from agent_audit_kit.scanners.taint_analysis import (
    _get_param_names,
    _import_names,
    _is_tool_function,
    _resolve_sink,
)

INTERP_RULE = "AAK-SHELL-QUOTED-INTERP-001"
PROFILE_RULE = "AAK-SHELL-DEFAULT-PROFILE-001"

_MAX_BYTES = 400_000

# Python sinks that hand a string to a shell, or hand argv to a program.
_PY_SHELL_SINKS = frozenset({
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
})

# Flags that mean "the next argv element is a program, not data". An argv list
# stops shell metacharacters; it does not stop an interpreter you asked for.
_EVAL_FLAGS = frozenset({
    "-c", "-e", "-E", "--eval", "--execute", "--command", "-command",
    "--code", "-code", "--exec", "-doString", "--do", "-b",
})

# Proof the author escaped the value. Any of these in the enclosing function
# clears the finding.
_PY_QUOTE_RE = re.compile(r"\bshlex\.(?:quote|join)\s*\(|\bpipes\.quote\s*\(")
_JS_QUOTE_RE = re.compile(
    r"""\bshell[-_]?quote\b|\bshellQuote\s*\(|\bshlex\b|\bescapeShellArg\s*\(""",
    re.IGNORECASE,
)

# JS/TS sinks. `exec`/`execSync` spawn a shell; `execFile`/`spawn` do not, and
# are only reachable here via the eval-flag path handled separately.
_JS_SHELL_SINK_RE = re.compile(
    r"\b(?:execAsync|execSync|exec|spawnSync|spawn|execFile|execFileSync)\s*\(",
)
_JS_SHELL_ONLY = frozenset({"execAsync", "execSync", "exec"})

# A `${...}` interpolation inside a template literal. It is applied to the
# template only up to its last `}` (see `_js_sinks`): a `${` after that can never
# close, but `[^}]*` still read from each one to the end of the template, so a
# template of unclosed `${` grew with the square of its length. No match can
# extend past the last `}`, so the interpolations are the same.
_JS_INTERP_RE = re.compile(r"\$\{([^}]*)\}")

# Tool-argument origins in a TS/JS MCP handler.
_JS_TOOL_ARG_RE = re.compile(
    r"""
    (?:
        request\.params\.arguments
      | params\.arguments
      | \bargs\b\s*\.
      | \bargs\b\s*\[
      | \binput\b\s*\.
      | destructur
    )
    """,
    re.VERBOSE,
)

# Opt-in gates: the tool is behind a flag, env var, or named profile.
_OPT_IN_RE = re.compile(
    r"""
    (?:
        \bos\.environ(?:\.get)?\s*[\[(]\s*["'][A-Z0-9_]*(?:ENABLE|ALLOW|UNSAFE|DANGER|EXPERIMENT)
      | \bgetenv\s*\(\s*["'][A-Z0-9_]*(?:ENABLE|ALLOW|UNSAFE|DANGER|EXPERIMENT)
      | \bprocess\.env\.[A-Z0-9_]*(?:ENABLE|ALLOW|UNSAFE|DANGER|EXPERIMENT)
      | \b(?:enable|allow)_(?:unsafe|shell|exec|command|dangerous)\w*
      | \bunsafe_mode\b
      | \bdangerously\w*
      | \bprofile\s*(?:==|!=|in|=)\s*["'](?:full|admin|unsafe|advanced|power)
      | \btool_?profile\b
      | \b--enable-\w+
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------
def _fmt_parts(node: ast.AST) -> tuple[bool, set[str]]:
    """Does ``node`` build a string by interpolation, and from which names?

    Covers f-strings, ``%``, ``str.format``, ``+`` concatenation and ``str.join``.
    Returns ``(is_interpolated, contributing_names)``.
    """
    names: set[str] = set()
    interpolated = False

    if isinstance(node, ast.JoinedStr):  # f"..."
        interpolated = True
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                names |= {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        # "cmd %s" % x    /    "cmd " + x
        interpolated = True
        names |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    elif isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("format", "join"):
            interpolated = True
            names |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    return interpolated, names


def _shell_template(node: ast.AST) -> str | None:
    """Rebuild the *shell* command string from the AST.

    Reading the Python source segment instead would count the literal's own
    delimiters as shell quoting — `f"lookup {name}"` has a double quote in the
    source and none in the command it runs. Interpolation sites come back as
    ``{name}`` so the quoting scan sees the shell string and nothing else.
    Returns None when the shape is not reconstructible.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    if isinstance(node, ast.Name):
        return "{" + node.id + "}"

    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner = _shell_template(value.value)
                parts.append(inner if inner is not None else "{...}")
        return "".join(parts)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _shell_template(node.left)
        right = _shell_template(node.right)
        if left is None or right is None:
            return None
        return left + right

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = _shell_template(node.left)
        if left is None:
            return None
        names = [n.id for n in ast.walk(node.right) if isinstance(n, ast.Name)]
        for name in names:
            left = re.sub(r"%[sdr]", "{" + name + "}", left, count=1)
        return left

    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            base = _shell_template(func.value)
            if base is None:
                return None
            names = [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]
            for name in names:
                base = base.replace("{}", "{" + name + "}", 1)
            return base

    return None


def _quote_context(template: str, marker: str) -> str:
    """Classify the shell quoting around ``marker`` in a command template.

    ``"double"`` is the interesting answer: it looks defended and is not, because
    ``$(...)``, backticks and ``${...}`` all expand inside double quotes.
    """
    idx = template.find("{" + marker + "}")
    if idx < 0:
        idx = template.find(marker)
    if idx < 0:
        return "bare"
    prefix = template[:idx]
    if prefix.count('"') % 2 == 1:
        return "double"
    if prefix.count("'") % 2 == 1:
        return "single"
    return "bare"


def _argv_eval_targets(call: ast.Call) -> list[ast.expr]:
    """Argv elements that follow an interpreter eval flag.

    All of them, not just the first: ``["stata-mp", "-b", "-e", cmd]`` puts a
    batch flag before the eval flag, and stopping at the first match lands on
    ``"-e"`` — a literal — instead of on ``cmd``.
    """
    if not call.args:
        return []
    first = call.args[0]
    if not isinstance(first, (ast.List, ast.Tuple)):
        return []
    targets: list[ast.expr] = []
    for i, element in enumerate(first.elts):
        if (
            isinstance(element, ast.Constant)
            and isinstance(element.value, str)
            and element.value in _EVAL_FLAGS
            and i + 1 < len(first.elts)
        ):
            targets.append(first.elts[i + 1])
    return targets


def _shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
            return bool(kw.value.value)
    return False


def _analyse_py_function(
    func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str, source: _PySource, imported: dict[str, str]
) -> tuple[list[Finding], bool]:
    """Returns (findings, reached_a_command_sink).

    A sink imported under another name (`from subprocess import run`) is read
    through `imported`, the file's import map, as AAK-TAINT-001 reads it.
    """
    params = _get_param_names(func)
    if not params:
        return [], False

    body_src = source.segment(func) or ""
    if _PY_QUOTE_RE.search(body_src):
        return [], False

    # One hop of local propagation: local name -> the template it was built from.
    tainted_locals: dict[str, tuple[str, int]] = {}
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None:
            continue
        interpolated, contributors = _fmt_parts(value)
        if not interpolated or not (contributors & params):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                template = _shell_template(value)
                if template is None:
                    template = source.segment(value) or ""
                tainted_locals[target.id] = (template, node.lineno)

    findings: list[Finding] = []
    reached_sink = False

    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        callee = _resolve_sink(node, imported)
        if callee not in _PY_SHELL_SINKS:
            continue
        reached_sink = True

        # Which expression carries the command?
        candidates: list[tuple[ast.expr, str]] = []
        eval_targets = _argv_eval_targets(node)
        if eval_targets:
            candidates.extend((target, "argv-eval") for target in eval_targets)
        elif node.args and (_shell_true(node) or callee[1] in ("system", "popen", "getoutput", "getstatusoutput")):
            candidates.append((node.args[0], "shell"))
        elif node.args and not isinstance(node.args[0], (ast.List, ast.Tuple)):
            candidates.append((node.args[0], "shell"))

        for expr, mode in candidates:
            template = ""
            line = node.lineno
            direct, contributors = _fmt_parts(expr)
            if direct and (contributors & params):
                template = _shell_template(expr) or source.segment(expr) or ""
                tainted_names = contributors & params
            elif isinstance(expr, ast.Name) and expr.id in tainted_locals:
                template, line = tainted_locals[expr.id]
                tainted_names = _names_in_template(template, params)
            else:
                continue

            param = sorted(tainted_names)[0] if tainted_names else "parameter"
            quoting = _quote_context(template, param)
            findings.append(
                make_finding(
                    INTERP_RULE,
                    rel,
                    _evidence(func.name, param, quoting, mode, template),
                    line,
                )
            )

    return findings, reached_sink


def _names_in_template(template: str, params: set[str]) -> set[str]:
    return {p for p in params if re.search(rf"\b{re.escape(p)}\b", template)}


_NON_BLANK_RE = re.compile(r"\S+")
_SNIPPET_CHARS = 110


@lru_cache(maxsize=8)
def _snippet(template: str) -> str:
    """`" ".join(template.split())[:110]`, reading only as far as that needs.

    Every finding quotes its template, and a template of many interpolations is
    many findings: splitting all of it for each would spend 6.8 seconds on the
    42,858 findings of a 375 KB template of distinct `${aN}`, growing with the
    square. The words are read until there are enough, none of them longer than
    the snippet, and a template is read once for all its findings.
    """
    words: list[str] = []
    size = -1
    for m in _NON_BLANK_RE.finditer(template):
        words.append(template[m.start() : min(m.end(), m.start() + _SNIPPET_CHARS)])
        size += len(words[-1]) + 1
        if size >= _SNIPPET_CHARS:
            break
    return " ".join(words)[:_SNIPPET_CHARS]


def _evidence(func_name: str, param: str, quoting: str, mode: str, template: str) -> str:
    snippet = _snippet(template)
    if mode == "argv-eval":
        why = (
            "argv element sits behind an interpreter eval flag, so the list form "
            "does not stop injection into the interpreter's own command language"
        )
    elif quoting == "double":
        why = (
            "interpolation site is inside double quotes, which do not stop "
            "$(...), backticks or ${...}"
        )
    elif quoting == "single":
        why = (
            "interpolation site is inside single quotes, which stop substitution "
            "but not a literal ' that closes the quoting"
        )
    else:
        why = "interpolation site is unquoted"
    return f"'{func_name}': parameter '{param}' -> shell command; {why} [{snippet}]"


def _scan_python(text: str, rel: str) -> tuple[list[Finding], list[str]]:
    try:
        tree = parse_python(text, rel)
    except SyntaxError:
        return [], []
    tools = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_tool_function(node)
    ]
    if not tools:
        return [], []
    # The template is followed recursively, so the tools are analysed in one
    # `walk_tree` (one hand-over to the worker before 3.11, not one per tool).
    return walk_tree(_analyse_py_tools, tools, rel, _PySource(text), _import_names(tree))


def _analyse_py_tools(
    tools: list[ast.FunctionDef | ast.AsyncFunctionDef], rel: str, source: _PySource,
    imported: dict[str, str],
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    exec_tools: list[str] = []
    for node in tools:
        found, reached = _analyse_py_function(node, rel, source, imported)
        findings.extend(found)
        if found and reached:
            exec_tools.append(node.name)
    return findings, exec_tools


# --------------------------------------------------------------------------
# TypeScript / JavaScript
# --------------------------------------------------------------------------
# A shell sink whose command is a bare identifier: `exec(cmd, ...)`.
_JS_FIRST_IDENT_RE = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*[,)]")

# How far back an assignment to that identifier is looked for.
_JS_LOCAL_WINDOW_LINES = 60

# What follows a name it is assigned to, up to the value: an optional type and
# `=`. Written `\s*(?::\s*[\w$<>\[\]|, ]+)?\s*=(?![=>])\s*`, a type's trailing
# blanks could go to the class or to `\s*`, and so could the blanks of a name
# with no type, so a long run of them with no `=` after it was split every way:
# 32,000 blanks took 1.6 seconds. Here the type runs from its first to its last
# non-blank, or is a single blank, so each run is read one way. The same text
# matches and every match ends where it did.
_JS_TYPED_ASSIGN = (
    r"\s*(?::(?:\s*[\w$<>\[\]|,](?:[ ]*[\w$<>\[\]|,])*|[^\S ]*[ ])\s*)?=(?![=>])\s*"
)
# A name a template literal is assigned to, and the assignment up to its backtick.
_JS_ASSIGNABLE_RE = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")
_JS_TEMPLATE_ASSIGN_RE = re.compile(_JS_TYPED_ASSIGN + "`")
_JS_TEMPLATE_ASSIGNMENT_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)" + _JS_TYPED_ASSIGN + "`")

_BACKTICK_RE = re.compile("`")
_NEWLINE_RE = re.compile("\n")
_INTERP_OPEN_RE = re.compile(r"\$\{")
_CLOSE_BRACE_RE = re.compile(r"\}")
_OPEN_BRACE_RE = re.compile(r"\{")
_DOUBLE_QUOTE_RE = re.compile('"')
_SINGLE_QUOTE_RE = re.compile("'")


def _positions(text: str, pattern: re.Pattern[str]) -> list[int]:
    return [m.start() for m in pattern.finditer(text)]


def _first_at(positions: list[int], start: int) -> float:
    """The first of ``positions`` at or after ``start``, or infinity."""
    i = bisect_left(positions, start)
    return positions[i] if i < len(positions) else math.inf


class _JsSink:
    """One shell sink and the interpolations its command carries."""

    __slots__ = ("sink", "pos", "line", "interps")

    def __init__(self, sink: str, pos: int, line: int, interps: list[tuple[str, str, str, str]]) -> None:
        self.sink = sink
        self.pos = pos
        self.line = line
        # (root name, quoting, mode, template)
        self.interps = interps


class _JsFile:
    """One TS/JS file, indexed once for every sink in it.

    Each sink used to read the file for itself: on to the next backtick, and
    back over everything before it, for its command template; sixty lines back,
    which a long line makes the whole file, for a local's assignment, with a
    regex compiled per name; and the whole prefix to count its line. A file of
    sinks grew with the square of its length (40 KB of `exec(cmd);` took a
    second). Each of those is now a lookup in positions found once, or a search
    that carries on from the last sink's, and a template's interpolations are
    read once however many sinks run it. Nothing is indexed until a file has a
    sink, and most have none.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._ticks_found: list[int] | None = None
        self._newlines_found: list[int] | None = None
        self._next: dict[str, tuple[int, float]] = {}
        self._templates: dict[int, tuple[str, list[tuple[str, str]]]] = {}
        self._assignments: dict[str, _JsAssignments] | None = None

    @property
    def _ticks(self) -> list[int]:
        if self._ticks_found is None:
            self._ticks_found = _positions(self.text, _BACKTICK_RE)
        return self._ticks_found

    @property
    def _newlines(self) -> list[int]:
        if self._newlines_found is None:
            self._newlines_found = _positions(self.text, _NEWLINE_RE)
        return self._newlines_found

    def _first(self, needle: str, start: int) -> float:
        """The first ``needle`` at or after ``start``, or infinity. The sinks ask
        in order, so each search starts where the last one found nothing."""
        asked, found = self._next.get(needle, (-1, -1.0))
        if not asked <= start <= found:
            at = self.text.find(needle, start)
            found = at if at >= 0 else math.inf
        self._next[needle] = (start, found)
        return found

    def template_at(self, start: int) -> tuple[str, list[tuple[str, str]]] | None:
        """The backtick template literal that starts at or after ``start``, and
        its interpolations, or None when there is none or a `;` or blank line
        comes before it (the literal belongs to another statement)."""
        i = bisect_left(self._ticks, start)
        if i + 1 >= len(self._ticks):
            return None  # no opening backtick, or none to close it
        opening = self._ticks[i]
        if self._first(";", start) < opening or self._first("\n\n", start) + 2 <= opening:
            return None
        return self._template(i)

    def _template(self, i: int) -> tuple[str, list[tuple[str, str]]]:
        hit = self._templates.get(i)
        if hit is None:
            template = self.text[self._ticks[i] + 1 : self._ticks[i + 1]]
            hit = self._templates[i] = (template, _template_interps(template))
        return hit

    def assigned(self, ident: str, before: int) -> list[tuple[str, str, str, str]]:
        """The interpolations of the templates assigned to ``ident`` shortly
        before a sink at ``before``.

        Every branch counts: nexus-mcp assigns ``cmd`` a different template per
        platform and then runs whichever was taken.
        """
        if self._assignments is None:
            read = set()
            for sink in _JS_SHELL_SINK_RE.finditer(self.text):
                first = _JS_FIRST_IDENT_RE.match(self.text, sink.end())
                if first:
                    read.add(first.group(1))
            self._assignments = _js_template_assignments(self.text, read)
        sites = self._assignments.get(ident)
        if sites is None:
            return []
        return sites.interps(self._window_start(before), before, self)

    def assigned_template(self, tick: int) -> tuple[str, list[tuple[str, str]]] | None:
        """The template an assignment's backtick at ``tick`` opens, if it closes."""
        i = bisect_left(self._ticks, tick)
        return self._template(i) if i + 1 < len(self._ticks) else None

    def _window_start(self, before: int) -> int:
        """Sixty lines back from ``before``, skipping blank lines.

        Each step goes to the last newline at least two characters back, so a
        newline right before the current one, a blank line, is not counted. The
        walk stops at the top of the file. It used to stop only when no newline
        was left, so from the newline at offset 0 it asked for the last newline
        before offset -1, which `rfind` counts from the end of the file: the
        window jumped past the sink and the template was lost in any file whose
        first line was blank.
        """
        start = before
        newlines = self._newlines
        for _ in range(_JS_LOCAL_WINDOW_LINES):
            i = bisect_right(newlines, start - 2) - 1
            if i < 0 or newlines[i] == 0:
                return 0
            start = newlines[i]
        return start


class _JsAssignments:
    """Where one name is assigned a template literal, and the interpolations
    of the window last asked for, extended as the sinks move down the file.

    A window is the assignments that start at or after its first line and end
    before its sink. Overlapping assignments end at the same backtick, so they
    add the same interpolations, and a window is a run of this list. Sinks come
    in order, so both ends only move down: the run grows at its end until its
    first line moves, and then starts again from the new first line. An
    assignment is read again once for each first line it falls under, sixty or
    so, however many sinks share them.
    """

    __slots__ = ("starts", "ends", "ticks", "_lo", "_hi", "_seen", "_merged")

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []
        self.ticks: list[int] = []
        self._lo = -1
        self._hi = 0
        self._seen: set[tuple[str, str]] = set()
        self._merged: list[tuple[str, str, str, str]] = []

    def interps(self, start: int, before: int, js: _JsFile) -> list[tuple[str, str, str, str]]:
        lo = bisect_left(self.starts, start)
        hi = bisect_right(self.ends, before)
        if lo != self._lo or hi < self._hi:
            self._lo, self._hi, self._seen, self._merged = lo, lo, set(), []
        while self._hi < hi:
            found = js.assigned_template(self.ticks[self._hi])
            self._hi += 1
            if found is None:
                continue
            template, interps = found
            for name, quoting in interps:
                if (name, quoting) not in self._seen:
                    self._seen.add((name, quoting))
                    self._merged.append((name, quoting, "shell", template))
        return list(self._merged)


def _js_template_assignments(text: str, names: set[str]) -> dict[str, _JsAssignments]:
    """Every assignment of a template literal to one of ``names``, by name.

    An assignment the sink reads, `(?<![\\w$.])name` + `_JS_TYPED_ASSIGN` + a
    backtick, names a whole run of name characters: the lookbehind starts it
    and the type or `=` after it ends it. So one pattern finds them all, for
    whichever of the names the sinks read (or, for a file whose sinks read many,
    for any name, which reads every name in the file once). It skips one kind:
    an assignment that starts inside another's type annotation (the second `x`
    of `x: x =` before a template), which ends at the same backtick, so those
    annotations are read again for one.
    """
    if len(names) > 64:
        pattern = _JS_TEMPLATE_ASSIGNMENT_RE
    else:
        alternatives = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        pattern = re.compile(rf"(?<![\w$.])({alternatives})" + _JS_TYPED_ASSIGN + "`")
    out: dict[str, _JsAssignments] = {}

    def add(name: str, start: int, end: int) -> None:
        sites = out.get(name)
        if sites is None:
            sites = out[name] = _JsAssignments()
        sites.starts.append(start)
        sites.ends.append(end)
        sites.ticks.append(end - 1)

    for m in pattern.finditer(text):
        if m.group(1) in names:
            add(m.group(1), m.start(), m.end())
        for inner in _JS_ASSIGNABLE_RE.finditer(text, m.end(1), m.end() - 1):
            tail = _JS_TEMPLATE_ASSIGN_RE.match(text, inner.end()) if inner.group() in names else None
            if tail:
                add(inner.group(), inner.start(), tail.end())
    return out


def _template_interps(template: str) -> list[tuple[str, str]]:
    """Each `${...}` in a command template, once per (name, quoting), in order.

    One command string can interpolate the same value more than once —
    CVE-2026-55157 uses `username` twice in one template. That is one defect,
    not two; so is one value in each branch of a platform switch.
    """
    exprs = _JS_INTERP_RE.findall(template, 0, template.rfind("}") + 1)
    if not exprs:
        return []
    quotings = _js_quotings(template, exprs)
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for expr in exprs:
        quoting = quotings[expr]
        name = expr.strip().split(".")[-1].split(" ")[0] or "argument"
        if (name, quoting) not in seen:
            seen.add((name, quoting))
            out.append((name, quoting))
    return out


def _js_quotings(template: str, exprs: list[str]) -> dict[str, str]:
    """`_quote_context(template, "${" + e + "}")` for every ``e`` in ``exprs``.

    That finds `{${e}}`, or failing that `${e}`, and counts the quotes before
    it. Asked once per interpolation, a template of many read itself once for
    each: 14,285 distinct `${aN}` (117 KB) took 1.3 seconds, growing with the
    square. An ``e`` never holds a `}`, so `${e}` occurs exactly where a `${` is
    followed by ``e`` and then the first `}` after it, and `{${e}}` is that
    with a `{` before and a `}` after. Walking the `${` openers once, each names
    the one ``e`` it can start, and only an ``e`` of a length some interpolation
    has is cut out to compare.
    """
    wanted = set(exprs)
    lengths = {len(e) for e in wanted}
    closes = _positions(template, _CLOSE_BRACE_RE)
    single: dict[str, int] = {}
    double: dict[str, int] = {}
    for m in _INTERP_OPEN_RE.finditer(template):
        at = m.start()
        i = bisect_left(closes, at + 2)
        if i == len(closes):
            break
        close = closes[i]
        if close - at - 2 not in lengths:
            continue
        expr = template[at + 2 : close]
        if expr not in wanted:
            continue
        single.setdefault(expr, at)
        if expr not in double and at and template[at - 1] == "{" and template.startswith("}", close + 1):
            double[expr] = at - 1
    doubles = _positions(template, _DOUBLE_QUOTE_RE)
    singles = _positions(template, _SINGLE_QUOTE_RE)
    out: dict[str, str] = {}
    for expr in wanted:
        idx = double.get(expr, single.get(expr, -1))
        if idx < 0:
            out[expr] = "bare"
        elif bisect_left(doubles, idx) % 2 == 1:
            out[expr] = "double"
        elif bisect_left(singles, idx) % 2 == 1:
            out[expr] = "single"
        else:
            out[expr] = "bare"
    return out


def _js_sinks(text: str) -> list[_JsSink]:
    """Every shell sink with an interpolated command, inline or through a local."""
    js: _JsFile | None = None  # indexed at the first sink: most files have none
    sinks: list[_JsSink] = []
    line, counted = 1, 0
    for match in _JS_SHELL_SINK_RE.finditer(text):
        sink = match.group(0).rstrip("(").strip()
        call_start = match.end()

        # `execFile`/`spawn` do not spawn a shell — only interesting when an
        # argv element rides behind an interpreter eval flag.
        if sink not in _JS_SHELL_ONLY:
            window = text[call_start : call_start + 400]
            if not any(f'"{f}"' in window or f"'{f}'" in window for f in _EVAL_FLAGS):
                continue

        mode = "shell" if sink in _JS_SHELL_ONLY else "argv-eval"
        if js is None:
            js = _JsFile(text)
        inline = js.template_at(call_start)
        interps: list[tuple[str, str, str, str]] = []
        if inline is not None:
            template, found = inline
            interps = [(name, quoting, mode, template) for name, quoting in found]
        elif sink in _JS_SHELL_ONLY:
            ident = _JS_FIRST_IDENT_RE.match(text, call_start)
            if ident:
                interps = js.assigned(ident.group(1), match.start())
        if interps:
            line += text.count("\n", counted, match.start())
            counted = match.start()
            sinks.append(_JsSink(sink, match.start(), line, interps))
    return sinks


def _scan_js(text: str, rel: str) -> tuple[list[Finding], list[str]]:
    if _JS_QUOTE_RE.search(text):
        return [], []
    if not _JS_TOOL_ARG_RE.search(text):
        return [], []

    findings: list[Finding] = []
    exec_tools: list[str] = []
    for found in _js_sinks(text):
        for name, quoting, mode, template in found.interps:
            findings.append(
                make_finding(
                    INTERP_RULE,
                    rel,
                    _evidence(found.sink, name, quoting, mode, template),
                    found.line,
                )
            )
            exec_tools.append(found.sink)
    return findings, exec_tools


# --------------------------------------------------------------------------
# One hop across files (CVE-2026-94031, nexus-mcp)
# --------------------------------------------------------------------------
# A tool handler passes its argument to `x.method(...)`, and `method`, defined
# in another file, interpolates that parameter into a shell command. The sink
# file carries no tool-argument marker, so `_scan_js` never looks at it.
# Matched by method name, not type, and one call deep.

_JS_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "with", "return", "typeof",
    "await", "new", "function", "else", "do", "try",
})

# A function or method header whose body opens with `{`. `_js_headers` finds
# what `finditer` over this finds, without its cost: tests hold it to that.
_JS_HEADER_RE = re.compile(
    r"""
    (?:\bfunction\s*\*?\s*(?P<fname>[A-Za-z_$][\w$]*)\s*\((?P<fparams>[^()]*)\)
      | (?P<mname>[A-Za-z_$][\w$]*)\s*\((?P<mparams>[^()]*)\)
        \s*(?::\s*[^{};=]*(?:\{[^{}]*\}[^{};=]*)?)?\s*(?=\{)
      | (?:(?P<aname>[A-Za-z_$][\w$]*)\s*=\s*)?(?:async\s*)?\((?P<aparams>[^()]*)\)
        \s*(?::\s*[^=;{]*?)?=>\s*(?=\{)
    )
    """,
    re.VERBOSE,
)


def _split_top_level(text: str, brackets: str = "([{<") -> list[str]:
    """Split on commas that sit outside every bracket pair in ``brackets``."""
    closers = {"(": ")", "[": "]", "{": "}", "<": ">"}
    close_set = {closers[b] for b in brackets}
    depth = 0
    parts: list[str] = []
    cur: list[str] = []
    for ch in text:
        if ch in brackets:
            depth += 1
        elif ch in close_set and depth:
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _js_param_names(params: str) -> list[str | None]:
    names: list[str | None] = []
    for raw in _split_top_level(params):
        p = re.sub(r"^\s*(?:(?:public|private|protected|readonly)\s+)*(?:\.\.\.)?", "", raw)
        m = re.match(r"[A-Za-z_$][\w$]*", p)
        names.append(m.group(0) if m and not p.startswith(("{", "[")) else None)
    return names


_BLANKS_RE = re.compile(r"\s*")
_SPACE_RE = re.compile(r"\s")
_NON_SPACE_RE = re.compile(r"\S")
_NAME_TAIL_RE = re.compile(r"[\w$]*")
_NAME_START_RE = re.compile(r"[A-Za-z_$]")
_WORD_CHAR_RE = re.compile(r"\w")
_NAME_RUN_RE = re.compile(r"[\w$]+")
_PAREN_RE = re.compile(r"[()]")
_OPEN_PAREN_RE = re.compile(r"\(")
_TYPE_STOP_RE = re.compile(r"[{};=]")
_BRACE_RE = re.compile(r"[{}]")
_ARROW_STOP_RE = re.compile(r"[=;{]")


class _Header:
    """One `_JS_HEADER_RE` match: where it is, the function it names, and its
    parameters. For a method whose return type is an object literal, the
    braces of that literal (`group`), which matter when a sink sits inside
    them (see `_JsOwners.owner`)."""

    __slots__ = ("start", "end", "func", "params", "group", "_positions")

    def __init__(self, start: int, end: int, func: str, params: str, group: tuple[int, int] | None) -> None:
        self.start = start
        self.end = end
        self.func = func
        self.params = params
        self.group = group
        self._positions: dict[str, int] | None = None

    def param_positions(self) -> dict[str, int]:
        """Each parameter name and its first position, as `params.index(name)`."""
        if self._positions is None:
            self._positions = {}
            for i, name in enumerate(_js_param_names(self.params)):
                if name is not None:
                    self._positions.setdefault(name, i)
        return self._positions


class _JsHeaderScan:
    """`_JS_HEADER_RE.finditer` over a whole file, in linear time.

    The regex let a method or arrow header start at every character of a name,
    and each start read the name to its end: a 16 KB word before a `(` took 2.8
    seconds and 160 KB took 279. Its return-type and arrow-type parts read on to
    the next `{`, `;` or `=` from every header that failed, and split blank runs
    every way. Here a header is tried only where one can start (a `(`, the first
    letter of a run of name characters, or a `function` or `async` that a `$`
    puts inside a run, which `\\b` and the literal still allow), and every part
    that reads far is a lookup in positions found once. Starting later in a run
    reads the same name end and the same rest, so it can only fail where the
    run's first letter failed.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._parens = _positions(text, _PAREN_RE)
        self._type_stops = _positions(text, _TYPE_STOP_RE)
        self._braces = _positions(text, _BRACE_RE)
        self._arrow_stops = _positions(text, _ARROW_STOP_RE)

    def headers(self) -> list[_Header]:
        text = self.text
        starts: list[tuple[int, int]] = [(p, 3) for p in _positions(text, _OPEN_PAREN_RE)]
        for run in _NAME_RUN_RE.finditer(text):
            first = _NAME_START_RE.search(text, run.start(), run.end())
            if first is None:
                continue
            starts.append((first.start(), 0))
            at = text.find("$function", first.start(), run.end())
            while at >= 0:
                starts.append((at + 1, 1))
                at = text.find("$function", at + 1, run.end())
            if run.end() - 5 > first.start() and text.startswith("async", run.end() - 5):
                starts.append((run.end() - 5, 2))
        starts.sort()
        out: list[_Header] = []
        resume = 0
        for pos, kind in starts:
            if pos < resume:
                continue
            if kind == 0:
                header = self._function(pos) or self._method(pos) or self._arrow(pos)
            elif kind == 1:
                header = self._function(pos)
            elif kind == 2:
                header = self._arrow_async(pos, pos, "")
            else:
                header = self._arrow_tail(pos, pos, "")
            if header is not None:
                out.append(header)
                resume = header.end
        return out

    def _blanks(self, i: int) -> int:
        m = _BLANKS_RE.match(self.text, i)
        return m.end() if m else i

    def _name_end(self, i: int) -> int | None:
        if not _NAME_START_RE.match(self.text, i):
            return None
        m = _NAME_TAIL_RE.match(self.text, i + 1)
        return m.end() if m else i + 1

    def _params(self, paren: int) -> int | None:
        """The `)` that ends `[^()]*` after the `(` at ``paren``."""
        i = bisect_left(self._parens, paren + 1)
        if i < len(self._parens) and self.text[self._parens[i]] == ")":
            return self._parens[i]
        return None

    @staticmethod
    def _next(positions: list[int], start: int) -> int | None:
        i = bisect_left(positions, start)
        return positions[i] if i < len(positions) else None

    def _function(self, p: int) -> _Header | None:
        """`\\bfunction\\s*\\*?\\s*NAME\\s*\\(PARAMS\\)`."""
        text = self.text
        if not text.startswith("function", p) or (p and _WORD_CHAR_RE.match(text, p - 1)):
            return None
        at = self._blanks(p + 8)
        if text.startswith("*", at):
            at = self._blanks(at + 1)
        name_end = self._name_end(at)
        if name_end is None:
            return None
        paren = self._blanks(name_end)
        if not text.startswith("(", paren):
            return None
        close = self._params(paren)
        if close is None:
            return None
        return _Header(p, close + 1, text[at:name_end], text[paren + 1 : close], None)

    def _method(self, p: int) -> _Header | None:
        """`NAME\\s*\\(PARAMS\\)`, an optional `: Type` with at most one object
        literal in it, and the body's `{`."""
        text = self.text
        name_end = self._name_end(p)
        if name_end is None:
            return None
        paren = self._blanks(name_end)
        if not text.startswith("(", paren):
            return None
        close = self._params(paren)
        if close is None:
            return None
        at = self._blanks(close + 1)
        func, params = text[p:name_end], text[paren + 1 : close]
        if text.startswith("{", at):
            return _Header(p, at, func, params, None)
        if not text.startswith(":", at):
            return None
        # The type runs to the first `{`, `}`, `;` or `=`; it must be a `{`.
        stop = self._next(self._type_stops, at + 1)
        if stop is None or text[stop] != "{":
            return None
        # An object literal there, then more type, ending at the body's `{`;
        # failing that, the `{` was the body's.
        inner = self._next(self._braces, stop + 1)
        if inner is not None and text[inner] == "}":
            body = self._next(self._type_stops, inner + 1)
            if body is not None and text[body] == "{":
                return _Header(p, body, func, params, (stop, inner))
        return _Header(p, stop, func, params, None)

    def _arrow(self, p: int) -> _Header | None:
        """`NAME\\s*=\\s*(?:async\\s*)?` before an arrow, or `async` alone."""
        text = self.text
        name_end = self._name_end(p)
        if name_end is not None:
            eq = self._blanks(name_end)
            if text.startswith("=", eq):
                at = self._blanks(eq + 1)
                func = text[p:name_end]
                if text.startswith("async", at):
                    header = self._arrow_async(p, at, func)
                    if header is not None:
                        return header
                elif text.startswith("(", at):
                    header = self._arrow_tail(p, at, func)
                    if header is not None:
                        return header
        return self._arrow_async(p, p, "")

    def _arrow_async(self, p: int, at: int, func: str) -> _Header | None:
        if not self.text.startswith("async", at):
            return None
        paren = self._blanks(at + 5)
        return self._arrow_tail(p, paren, func) if self.text.startswith("(", paren) else None

    def _arrow_tail(self, p: int, paren: int, func: str) -> _Header | None:
        """`\\((?P<aparams>[^()]*)\\)\\s*(?::\\s*[^=;{]*?)?=>\\s*(?=\\{)` at ``paren``."""
        text = self.text
        close = self._params(paren)
        if close is None:
            return None
        at = self._blanks(close + 1)
        if text.startswith(":", at):
            # The lazy type stops at its first `=`, `;` or `{`, which must open `=>`.
            arrow = self._next(self._arrow_stops, self._blanks(at + 1))
            if arrow is None or not text.startswith("=>", arrow):
                return None
        elif text.startswith("=>", at):
            arrow = at
        else:
            return None
        body = self._blanks(arrow + 2)
        if not text.startswith("{", body):
            return None
        return _Header(p, body, func, text[paren + 1 : close], None)


def _js_headers(text: str) -> list[_Header]:
    return _JsHeaderScan(text).headers()


class _RightmostAtMost:
    """Over a fixed list of numbers: the rightmost index below ``limit`` whose
    value is at most ``ceiling``, in logarithmic time (a min segment tree)."""

    def __init__(self, values: list[int]) -> None:
        size = 1
        while size < len(values):
            size *= 2
        tree: list[float] = [math.inf] * (2 * size)
        tree[size : size + len(values)] = values
        for i in range(size - 1, 0, -1):
            tree[i] = min(tree[2 * i], tree[2 * i + 1])
        self._size = size
        self._tree = tree

    def find(self, limit: int, ceiling: int) -> int:
        tree, size = self._tree, self._size
        lo, hi = size, size + limit
        left: list[int] = []
        right: list[int] = []
        while lo < hi:
            if lo & 1:
                left.append(lo)
                lo += 1
            if hi & 1:
                hi -= 1
                right.append(hi)
            lo >>= 1
            hi >>= 1
        for node in right + left[::-1]:
            if tree[node] <= ceiling:
                while node < size:
                    node = 2 * node + 1 if tree[2 * node + 1] <= ceiling else 2 * node
                return node - size
        return -1


class _JsOwners:
    """The nearest function around a sink that takes its interpolated name,
    for every sink in one file.

    Each sink used to run `_JS_HEADER_RE` from the top of the file to itself
    and walk the headers back, counting braces from each body to the sink.
    The headers are now found once and each answer is a few lookups: the
    headers before a sink are a prefix of the file's, and the ones whose body
    is still open there are those whose body's brace depth is at most the
    sink's, the last of which a segment tree finds.

    A sink cut the regex at itself, so one header can differ: the first that
    runs past the sink. Nothing in it can start a header whose body is open at
    the sink, except when the sink sits inside the object-literal return type
    of a method (`foo(name): {exec(cmd)} {`): cut there, the method's header
    ends at that literal's `{`, a body that encloses the sink.
    """

    def __init__(self, text: str) -> None:
        self._headers = _js_headers(text)
        self._ends = [h.end for h in self._headers]
        self._opens = _positions(text, _OPEN_BRACE_RE)
        self._closes = _positions(text, _CLOSE_BRACE_RE)
        self._names: dict[str, tuple[list[int], list[tuple[str, int]], _RightmostAtMost]] = {}
        groups: dict[str, list[tuple[int, str, int, int]]] = {}
        for k, h in enumerate(self._headers):
            if h.func in _JS_KEYWORDS or not h.func:
                continue
            body = _first_at(self._opens, h.end)
            if body == math.inf:
                continue
            depth = self._depth(int(body) + 1)
            for name, index in h.param_positions().items():
                groups.setdefault(name, []).append((k, h.func, index, depth))
        for name, entries in groups.items():
            self._names[name] = (
                [k for k, _, _, _ in entries],
                [(func, index) for _, func, index, _ in entries],
                _RightmostAtMost([depth for _, _, _, depth in entries]),
            )

    def _depth(self, i: int) -> int:
        return bisect_left(self._opens, i) - bisect_left(self._closes, i)

    def owner(self, pos: int, name: str) -> tuple[str, int] | None:
        headers = self._headers
        j = bisect_right(self._ends, pos)
        if j < len(headers):
            h = headers[j]
            if h.start < pos and h.group is not None and h.group[0] < pos < h.group[1]:
                index = h.param_positions().get(name)
                if index is not None and h.func not in _JS_KEYWORDS:
                    return h.func, index
        entry = self._names.get(name)
        if entry is None:
            return None
        ks, owners, depths = entry
        # Headers that end at or before the last `{` before the sink have their
        # body before it; any later one is a `function` whose body is after it.
        last_open = bisect_left(self._opens, pos) - 1
        limit = bisect_right(self._ends, self._opens[last_open]) if last_open >= 0 else 0
        found = depths.find(bisect_left(ks, limit), self._depth(pos))
        return owners[found] if found >= 0 else None


_BRACKET_RE = re.compile(r"[\[\]]")


def _strip_subscripts(expr: str) -> str:
    """`TABLE[key]` is the table's value, not the key: drop what indexes it.

    This removed the innermost `[...]` and went round again until nothing
    changed, a pass per level of nesting. A pair is removed exactly when its
    brackets match, so one pass with a stack does the same: a `]` cuts back to
    the `[` it closes, and an unmatched bracket of either kind stays.
    """
    if "[" not in expr:
        return expr
    pieces: list[str] = []
    opens: list[int] = []
    last = 0
    for m in _BRACKET_RE.finditer(expr):
        pieces.append(expr[last : m.start()])
        last = m.end()
        if m.group() == "[":
            opens.append(len(pieces))
            pieces.append("[")
        elif opens:
            del pieces[opens.pop() :]
        else:
            pieces.append("]")
    pieces.append(expr[last:])
    return "".join(pieces)


_JS_ARGS_WORD_RE = re.compile(r"\b(?:args|arguments|input)\b")
# A name the tainted set can hold, where `(?<![\w$.])name(?![\w$])` finds it.
_JS_TAINT_TOKEN_RE = re.compile(r"(?<![\w$.])[\w$]+")


def _js_derived(bare: str, tainted: set[str], destructure: bool = False) -> bool:
    """Is an expression, its subscripts already stripped, tool-derived?"""
    if _JS_TOOL_ARG_RE.search(bare):
        return True
    if destructure and _JS_ARGS_WORD_RE.search(bare):
        return True
    return not tainted.isdisjoint(_JS_TAINT_TOKEN_RE.findall(bare))


_JS_DECLARE_RE = re.compile(r"\b(?:const|let|var)")
_JS_NAME_RE = re.compile(r"[A-Za-z_$][\w$]*")
_JS_RHS_STOP_RE = re.compile(r"[;\n]")
_JS_ANNOTATION_STOP_RE = re.compile(r"[=;\n]")


class _JsDeclarations:
    """`finditer` over the two declaration patterns `_js_tool_derived_names`
    reads, without their cost:

        \\b(?:const|let|var)\\s+(NAME)\\s*(?::[^=;\\n]+)?=(?![=>])\\s*([^;\\n]+)
        \\b(?:const|let|var)\\s*\\{([^}]*)\\}\\s*(?::[^=;\\n]+)?=\\s*([^;\\n]+)

    Each read a type annotation on to the next `=`, `;` or newline, and the
    second a destructuring list on to the next `}`, from every declaration
    keyword, so both grew with the square: 72 KB of `const a: ` took 2.8
    seconds and 56 KB of `const {` took 0.9. A match can start only at a
    keyword, and each far read is now a lookup in positions found once.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._closes = _positions(text, _CLOSE_BRACE_RE)
        self._annotation_stops = _positions(text, _JS_ANNOTATION_STOP_RE)
        self._rhs_stops = _positions(text, _JS_RHS_STOP_RE)
        self._rhs: dict[int, tuple[str, int] | None] = {}

    def assignments(self) -> list[tuple[list[str], str]]:
        keywords = [(m.start(), m.end()) for m in _JS_DECLARE_RE.finditer(self.text)]
        out: list[tuple[list[str], str]] = []
        for parse in (self._single, self._destructured):
            resume = 0
            for start, after in keywords:
                if start < resume:
                    continue
                found = parse(after)
                if found is not None:
                    names, rhs, resume = found
                    out.append((names, rhs))
        return out

    def _blanks(self, i: int) -> int:
        m = _BLANKS_RE.match(self.text, i)
        return m.end() if m else i

    def _single(self, after: int) -> tuple[list[str], str, int] | None:
        name_at = self._blanks(after)
        if name_at == after:
            return None  # `\s+`
        name = _JS_NAME_RE.match(self.text, name_at)
        if name is None:
            return None
        eq = self._equals(self._blanks(name.end()), strict=True)
        if eq is None:
            return None
        rhs = self._value(eq)
        return None if rhs is None else ([name.group()], rhs[0], rhs[1])

    def _destructured(self, after: int) -> tuple[list[str], str, int] | None:
        text = self.text
        brace = self._blanks(after)
        if not text.startswith("{", brace):
            return None
        i = bisect_left(self._closes, brace + 1)
        if i == len(self._closes):
            return None
        close = self._closes[i]
        eq = self._equals(self._blanks(close + 1), strict=False)
        if eq is None:
            return None
        rhs = self._value(eq)
        if rhs is None:
            return None
        bound = []
        for part in _split_top_level(text[brace + 1 : close]):
            local = part.split(":")[-1].split("=")[0].strip().lstrip(".")
            if _JS_NAME_RE.fullmatch(local):
                bound.append(local)
        return bound, rhs[0], rhs[1]

    def _equals(self, at: int, strict: bool) -> int | None:
        """Where `(?::[^=;\\n]+)?=` puts its `=` from ``at``; the first pattern
        also refuses an `=` followed by `=` or `>`."""
        text = self.text
        if text.startswith(":", at):
            i = bisect_left(self._annotation_stops, at + 1)
            if i == len(self._annotation_stops):
                return None
            eq = self._annotation_stops[i]
            if eq < at + 2 or text[eq] != "=":
                return None
        elif text.startswith("=", at):
            eq = at
        else:
            return None
        if strict and text[eq + 1 : eq + 2] in ("=", ">"):
            return None
        return eq

    def _value(self, eq: int) -> tuple[str, int] | None:
        """`\\s*([^;\\n]+)` after the `=` at ``eq``: the right-hand side and
        where the match ends. With nothing after the blanks but `;` or a
        newline, the blanks give back their last character that is not a
        newline. Every declaration that reaches one `=` reads the same, so it is
        read once."""
        if eq in self._rhs:
            return self._rhs[eq]
        text = self.text
        start = eq + 1
        at = self._blanks(start)
        i = bisect_left(self._rhs_stops, at)
        stop = self._rhs_stops[i] if i < len(self._rhs_stops) else len(text)
        found: tuple[str, int] | None
        if stop > at:
            found = (text[at:stop], stop)
        else:
            kept = len(text[start:at].rstrip("\n"))
            found = (text[start + kept - 1], start + kept) if kept else None
        self._rhs[eq] = found
        return found


def _js_tool_derived_names(text: str) -> set[str]:
    """Locals a handler file assigns from a tool argument, to a fixed point.

    The old loop rescanned every assignment against every tainted name until a
    pass changed nothing, with a regex compiled per name: a chain of locals
    listed backwards, so each pass found one more, took 6.3 seconds at 8 KB and
    grew with the cube. A name's taint never changes once set, so each
    assignment's right-hand side is read once, for its names, and fires the
    first time one of them is tainted.
    """
    tainted: set[str] = set()
    waiting: dict[str, list[int]] = {}
    assigns = _JsDeclarations(text).assignments()
    fired = [False] * len(assigns)
    pending: list[str] = []

    def fire(i: int) -> None:
        fired[i] = True
        for name in assigns[i][0]:
            if name not in tainted:
                tainted.add(name)
                pending.append(name)

    for i, (names, rhs) in enumerate(assigns):
        if not names:
            continue  # binds nothing, so it can never add a name
        bare = _strip_subscripts(rhs)
        destructure = len(names) > 1 or rhs.strip() in {"args", "input"}
        if _js_derived(bare, set(), destructure):
            fire(i)
            continue
        for token in set(_JS_TAINT_TOKEN_RE.findall(bare)):
            waiting.setdefault(token, []).append(i)
    while pending:
        for i in waiting.pop(pending.pop(), []):
            if not fired[i]:
                fire(i)
    return tainted


_JS_CALL_SITE_RE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")
_JS_DEFINITION_KEYWORDS_RE = re.compile(r"(?:public|private|protected|static|async)\s+")
_JS_ARG_SPECIAL_RE = re.compile(r"[,()\[\]{}]")


class _JsHandler:
    """A tool-handler file, read once for every function the sink files ask
    about: which call passes a tool-derived value at a given position.

    Each question used to work out the file's tool-derived names again, read
    the whole file for the function's call sites, and for each one read its
    line back to the start and its arguments forward to the closing paren, so
    nested calls read their arguments once per level: 20 KB of nested `run(`
    took 4.2 seconds, growing with the square. A nested chain whose brackets
    straddle the arguments still read each level whole, both to split the
    arguments and to strip and search one (see `_argument` and `_BareSpans`).
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._tainted: set[str] | None = None
        self._calls: dict[str, list[tuple[int, int]]] | None = None
        self._answers: dict[tuple[str, int], int | None] = {}
        self._newlines: list[int] = []
        self._paren_close: dict[int, int] = {}
        self._bracket_close: dict[int, int] = {}
        self._commas: list[int] = []
        self._separators: _LeftmostBelow | None = None
        self._first_non_blank: dict[int, int] = {}
        self._bare: _BareSpans | None = None
        self._indexed = False
        self._chains: dict[int, set[int]] = {}

    def tool_arg_call(self, func: str, index: int) -> int | None:
        """Line of a call to ``func`` whose argument at ``index`` is tool-derived."""
        key = (func, index)
        if key not in self._answers:
            self._answers[key] = self._first_call(func, index)
        return self._answers[key]

    def _index(self) -> None:
        """Paren and bracket pairs and the argument separators, found once."""
        if self._indexed:
            return
        self._indexed = True
        text = self.text
        self._newlines = _positions(text, _NEWLINE_RE)
        parens: list[int] = []
        groups: list[int] = []
        brackets: list[int] = []
        around: list[int] = []
        for m in _JS_ARG_SPECIAL_RE.finditer(text):
            at, ch = m.start(), m.group()
            if ch == ",":
                self._commas.append(at)
                around.append(groups[-1] if groups else -1)
                continue
            if ch in "([{":
                groups.append(at)
            elif groups:
                groups.pop()
            if ch == "(":
                parens.append(at)
            elif ch == ")" and parens:
                self._paren_close[parens.pop()] = at
            elif ch == "[":
                brackets.append(at)
            elif ch == "]" and brackets:
                self._bracket_close[brackets.pop()] = at
        self._separators = _LeftmostBelow(around)

    def _first_call(self, func: str, index: int) -> int | None:
        if self._tainted is None:
            self._tainted = _js_tool_derived_names(self.text)
        if self._calls is None:
            self._calls = {}
            for m in _JS_CALL_SITE_RE.finditer(self.text):
                self._calls.setdefault(m.group(1), []).append((m.start(), m.end() - 1))
        calls = self._calls.get(func)
        if not calls:
            return None
        self._index()
        if self._bare is None:
            self._bare = _BareSpans(self.text, self._tainted, self._bracket_close)
        for start, paren in calls:
            if self._is_definition(start):
                continue
            close = self._paren_close.get(paren)
            if close is None:
                continue
            span = self._argument(paren + 1, close, index)
            if span is not None and self._bare.derived(*span):
                return bisect_left(self._newlines, start) + 1
        return None

    def _is_definition(self, start: int) -> bool:
        """`\\bfunction\\s*$` or `^\\s*(?:(?:public|...|async)\\s+)*$` on the line
        before the call: a definition, not a call."""
        text = self.text
        line = bisect_left(self._newlines, start)
        line_start = self._newlines[line - 1] + 1 if line else 0
        end = start
        while end > line_start and _SPACE_RE.match(text, end - 1):
            end -= 1
        word = end - 8
        if word >= line_start and text.startswith("function", word):
            if word == line_start or not _WORD_CHAR_RE.match(text, word - 1):
                return True
        chain = self._chains.get(line_start)
        if chain is None:
            line_end = self._newlines[line] if line < len(self._newlines) else len(text)
            at = _BLANKS_RE.match(text, line_start, line_end)
            pos = at.end() if at else line_start
            chain = {pos}
            while True:
                m = _JS_DEFINITION_KEYWORDS_RE.match(text, pos, line_end)
                if m is None:
                    break
                pos = m.end()
                chain.add(pos)
            self._chains[line_start] = chain
        return start in chain

    def _argument(self, begin: int, close: int, index: int) -> tuple[int, int] | None:
        """The span of `_split_top_level(text[begin:close], "([{")[index]`.

        A comma separates arguments when every opener after ``begin`` is closed
        by then, counting closers of any kind as `_split_top_level` does: when
        the innermost group still open at it, matched across all three kinds,
        opened before ``begin``. (A closer at depth zero changes nothing there
        and pops a group opened before ``begin`` here, which agrees.) The
        separators used to be walked from ``begin``, stepping over each group,
        so a `]` that closed a call's `(` left the rest of the chain at depth
        zero for it: `run(]` nested 10,000 deep took 10.5 seconds, growing with
        the square. Each separator is now a lookup in a tree over the commas.
        """
        commas, separators = self._commas, self._separators
        assert separators is not None  # built by `_index`
        lo, hi = bisect_left(commas, begin), bisect_left(commas, close)
        part = begin
        for _ in range(index):
            i = separators.find(lo, hi, begin)
            if i < 0:
                return None
            part, lo = commas[i] + 1, i + 1
        i = separators.find(lo, hi, begin)
        if i >= 0:
            return part, commas[i]
        return (part, close) if self._non_blank(part, close) else None

    def _non_blank(self, begin: int, end: int) -> bool:
        """`text[begin:end].strip()`, each blank run read once: the same long
        run can open the last argument of every level of a chain."""
        first = self._first_non_blank.get(begin)
        if first is None:
            m = _NON_SPACE_RE.search(self.text, begin)
            first = self._first_non_blank[begin] = m.start() if m else len(self.text)
        return first < end


class _LeftmostBelow:
    """Over a fixed list of numbers: the leftmost index in ``[lo, hi)`` whose
    value is below ``ceiling``, in logarithmic time (a min segment tree)."""

    def __init__(self, values: list[int]) -> None:
        size = 1
        while size < len(values):
            size *= 2
        tree: list[float] = [math.inf] * (2 * size)
        tree[size : size + len(values)] = values
        for i in range(size - 1, 0, -1):
            left, right = tree[2 * i], tree[2 * i + 1]
            tree[i] = left if left < right else right
        self._size = size
        self._tree = tree

    def find(self, lo: int, hi: int, ceiling: int) -> int:
        tree, size = self._tree, self._size
        lo, hi = lo + size, hi + size
        left: list[int] = []
        right: list[int] = []
        while lo < hi:
            if lo & 1:
                left.append(lo)
                lo += 1
            if hi & 1:
                hi -= 1
                right.append(hi)
            lo >>= 1
            hi >>= 1
        for node in left + right[::-1]:
            if tree[node] < ceiling:
                while node < size:
                    node = 2 * node if tree[2 * node] < ceiling else 2 * node + 1
                return node - size
        return -1


# What a stripped argument is searched for, split so a match at any place can be
# looked up: `_JS_TOOL_ARG_RE`'s literals (its `request.params.arguments` holds
# `params.arguments`), its keyword forms with the `\b` before them and without,
# and an `args` that a following `[` would complete.
_JS_TOOL_LITERAL_RE = re.compile(r"params\.arguments|destructur")
_JS_TOOL_WORD_RE = re.compile(r"\bargs\b\s*[.\[]|\binput\b\s*\.")
_JS_TOOL_WORD_TAIL_RE = re.compile(r"args\b\s*[.\[]|input\b\s*\.")
_JS_ARGS_BLANKS_RE = re.compile(r"args\s*")
_JS_TOKEN_RUN_RE = re.compile(r"[\w$]+")
_JS_TOKEN_TAIL_RE = re.compile(r"[\w$]*\Z")
_JS_TOKEN_CHAR_RE = re.compile(r"[\w$]")


class _BareSpans:
    """`_js_derived(_strip_subscripts(text[a:b]), tainted)` for any span of one
    handler file, in logarithmic time, without cutting the span out.

    `_first_call` used to cut each call's argument out, strip its subscripts
    and search what was left. An argument that read as part of one already
    found clean was skipped, unless a pair the outer one cut reached into it, so
    a nested chain whose brackets straddle the arguments was read whole at every
    level: 70 KB of `run(` nested in `[)]` pairs took 21 seconds, growing with
    the square.

    The strip keeps a character exactly when the innermost bracket pair around
    it, its own brackets included, is not wholly inside the span. So what is
    left is, in order, the direct content (the pair less the pairs inside it) of
    the pairs that hold the start and end inside the span, from the innermost
    out; of the one around the whole span, or the file; and of the pairs that
    start inside the span and hold its end, from the outermost in. Each part is
    a run of one pair's direct content, and every pair's is laid out once, in
    one string. No match crosses from one part to the next: none holds the `]`
    that ends a part on the start side, and only `args\\s*\\[` ends in the `[`
    that opens one on the end side. Inside a part, a match is one in the laid-
    out content unless it touches an end of the part, where its neighbours
    differ, so only the ends are read. A pair between the two ends of a chain
    has the same part whichever span it straddles, so its answer is kept, and
    a chain asks only for the nearest pair below its top that matched.
    """

    def __init__(self, text: str, tainted: set[str], bracket_close: dict[int, int]) -> None:
        self._tainted = tainted
        self._lengths = {len(name) for name in tainted}
        self._longest = max(self._lengths, default=0)
        # Node 0 is the file, around everything; the pairs follow in order.
        self._starts = [-1]
        self._ends = [len(text) + 1]
        self._parent = [0]
        self._depth = [0]
        self._jump = [0]  # skip pointers, for a logarithmic climb
        self._brackets: list[int] = []
        self._owner: list[int] = []  # the node each bracket is a character of
        self._after: list[int] = []  # the node open after each bracket
        stretches: list[list[tuple[int, int]]] = [[]]
        node, last = 0, 0
        for m in _BRACKET_RE.finditer(text):
            at = m.start()
            if m.group() == "[" and at in bracket_close:
                if at > last:
                    stretches[node].append((last, at))
                parent, node, last = node, len(self._starts), at
                self._add(at, bracket_close[at], parent)
                stretches.append([])
                owner = node
            elif m.group() == "]" and node:
                # The open pair's own: `bracket_close` gave each `]` the
                # innermost `[` still open, and an unmatched one would have
                # taken it, so the innermost open `[` is that of a pair.
                stretches[node].append((last, at + 1))
                owner, node, last = node, self._parent[node], at + 1
            else:
                owner = node  # unmatched: a character of the open pair
            self._brackets.append(at)
            self._owner.append(owner)
            self._after.append(node)
        if len(text) > last:
            stretches[node].append((last, len(text)))
        self._lay_out(text, stretches)
        self._left: dict[int, int] = {}
        self._right: dict[int, int] = {}

    def _add(self, start: int, end: int, parent: int) -> None:
        depth, jump = self._depth, self._jump
        self._starts.append(start)
        self._ends.append(end)
        self._parent.append(parent)
        depth.append(depth[parent] + 1)
        j = jump[parent]
        even = depth[parent] - depth[j] == depth[j] - depth[jump[j]]
        jump.append(jump[j] if even else parent)

    def _lay_out(self, text: str, stretches: list[list[tuple[int, int]]]) -> None:
        """Every node's direct content, each followed by a NUL, which no match
        holds, so none runs from one node's into the next."""
        parts: list[str] = []
        self._g: list[int] = []  # where each stretch is laid out
        self._raw: list[int] = []  # where it is in the file
        self._len: list[int] = []
        self._first: list[int] = []  # each node's first stretch
        self._g0: list[int] = []  # each node's direct content, laid out
        self._g1: list[int] = []
        g = 0
        for pieces in stretches:
            self._first.append(len(self._g))
            self._g0.append(g)
            for begin, end in pieces:
                self._g.append(g)
                self._raw.append(begin)
                self._len.append(end - begin)
                parts.append(text[begin:end])
                g += end - begin
            self._g1.append(g)
            parts.append("\0")
            g += 1
        self._first.append(len(self._g))
        laid = self._laid = "".join(parts)
        self._tok_t: list[int] = []
        self._tok_e: list[int] = []
        if self._tainted:
            for m in _JS_TAINT_TOKEN_RE.finditer(laid):
                if m.group() in self._tainted:
                    self._tok_t.append(m.start())
                    self._tok_e.append(m.end())
        self._lit_t, self._lit_e = _spans(_JS_TOOL_LITERAL_RE, laid)
        self._word_t, self._word_e = _spans(_JS_TOOL_WORD_RE, laid)
        self._word_at = dict(zip(*_spans(_JS_TOOL_WORD_TAIL_RE, laid)))
        args_t, self._args_w = _spans(_JS_ARGS_BLANKS_RE, laid)
        self._args_t4 = [t + 4 for t in args_t]
        self._args_bounded = [t == 0 or not _WORD_CHAR_RE.match(laid, t - 1) for t in args_t]

    def derived(self, a: int, b: int) -> bool:
        """Is `_strip_subscripts(text[a:b])` tool-derived?"""
        starts, ends, parent, jump, depth = self._starts, self._ends, self._parent, self._jump, self._depth
        x = self._enclosing(a)
        if x and ends[x] < b:
            # The pairs that hold `a` and end inside the span, innermost first.
            top = x
            while parent[top] and ends[parent[top]] < b:
                top = jump[top] if jump[top] and ends[jump[top]] < b else parent[top]
            if self._part(self._g_at(x, a), self._g1[x], False):
                return True
            if top != x:
                hit = self._nearest(x, self._left, self._after_child)
                if hit and depth[hit] > depth[top]:
                    return True
            around = parent[top]
            u = self._g_at(around, ends[top] + 1)
        else:
            around, u = x, self._g_at(x, a)
        y = self._enclosing(b)
        if not (y and starts[y] >= a):
            return self._part(u, self._g_at(around, b), False)
        # The pairs that start inside the span and hold `b`, outermost first.
        top = y
        while parent[top] and starts[parent[top]] >= a:
            top = jump[top] if jump[top] and starts[jump[top]] >= a else parent[top]
        if self._part(u, self._g_at(around, starts[top]), True):
            return True
        if top != y:
            hit = self._nearest(y, self._right, self._before_child)
            if hit and depth[hit] > depth[top]:
                return True
        return self._part(self._g0[y], self._g_at(y, b), False)

    def _enclosing(self, p: int) -> int:
        """The innermost pair that starts before ``p`` and ends at or after it."""
        i = bisect_left(self._brackets, p)
        if i < len(self._brackets) and self._brackets[i] == p:
            node = self._owner[i]
            return self._parent[node] if self._starts[node] == p else node
        return self._after[i - 1] if i else 0

    def _g_at(self, node: int, p: int) -> int:
        """Where the node's direct content resumes at or after ``p``, laid out."""
        lo, hi = self._first[node], self._first[node + 1]
        i = bisect_right(self._raw, p, lo, hi) - 1
        if i >= lo and p < self._raw[i] + self._len[i]:
            return self._g[i] + p - self._raw[i]
        return self._g[i + 1] if i + 1 < hi else self._g1[node]

    def _after_child(self, child: int) -> bool:
        """Does the part after ``child`` in its parent match, as a span that
        starts inside ``child`` and ends past the parent's `]` leaves it?"""
        up = self._parent[child]
        return self._part(self._g_at(up, self._ends[child] + 1), self._g1[up], False)

    def _before_child(self, child: int) -> bool:
        """Does the part before ``child`` in its parent match, as a span that
        starts before the parent's `[` and ends inside ``child`` leaves it?"""
        up = self._parent[child]
        return self._part(self._g0[up], self._g_at(up, self._starts[child]), True)

    def _nearest(self, node: int, known: dict[int, int], matches: Callable[[int], bool]) -> int:
        """The nearest pair from ``node`` up whose part matches, or 0. Each pair
        is asked once."""
        path: list[int] = []
        while node and node not in known:
            path.append(node)
            node = self._parent[node]
        found = known[node] if node else 0
        for pair in reversed(path):
            if matches(pair):
                found = pair
            known[pair] = found
        return found

    def _part(self, u: int, v: int, bracket_after: bool) -> bool:
        """Does ``laid[u:v]`` match, with a `[` after it when ``bracket_after``?

        A match that does not touch an end of the part is one in the laid-out
        content, whose first is found by a bisection. At the start, a word or a
        keyword has the start of the part before it; at the end, a word is cut
        where the part ends, and an `args` is completed by the `[` after it.
        """
        if u >= v:
            return False
        i = bisect_right(self._tok_t, u)
        if i < len(self._tok_t) and self._tok_e[i] <= v:
            return True
        i = bisect_left(self._lit_t, u)
        if i < len(self._lit_t) and self._lit_e[i] <= v:
            return True
        i = bisect_right(self._word_t, u)
        if i < len(self._word_t) and self._word_e[i] <= v:
            return True
        end = self._word_at.get(u)
        if end is not None and end <= v:
            return True
        if self._tainted and self._cut_word(u, v):
            return True
        if bracket_after:
            i = bisect_right(self._args_t4, v) - 1
            if i >= 0:
                t = self._args_t4[i] - 4
                if t >= u and self._args_w[i] >= v and (t == u or self._args_bounded[i]):
                    return True
        return False

    def _cut_word(self, u: int, v: int) -> bool:
        """Is the word at either end of ``laid[u:v]``, cut there, tainted?

        A name is no longer than the longest tainted one, so neither read goes
        further than that.
        """
        laid, longest = self._laid, self._longest
        word = _JS_TOKEN_RUN_RE.match(laid, u, min(v, u + longest + 1))
        if word and self._is_tainted(u, word.end()):
            return True
        if not _JS_TOKEN_CHAR_RE.match(laid, v):
            return False  # the word ends with the part, which a match inside it already covers
        lo = max(u + 1, v - longest)
        tail = _JS_TOKEN_TAIL_RE.search(laid, lo, v)
        start = tail.start() if tail else v
        if start == v or (start == lo and _JS_TOKEN_CHAR_RE.match(laid, lo - 1)):
            return False  # no word, or one that starts at ``u`` or is too long
        return laid[start - 1] != "." and self._is_tainted(start, v)

    def _is_tainted(self, begin: int, end: int) -> bool:
        return end - begin in self._lengths and self._laid[begin:end] in self._tainted


def _spans(pattern: re.Pattern[str], text: str) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    for m in pattern.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    return starts, ends


def _cross_file_js(texts: dict[str, str]) -> list[Finding]:
    handlers = {rel: t for rel, t in texts.items() if _JS_TOOL_ARG_RE.search(t)}
    readers = [(hrel, _JsHandler(htext)) for hrel, htext in sorted(handlers.items())]
    findings: list[Finding] = []
    for rel, text in texts.items():
        if rel in handlers or _JS_QUOTE_RE.search(text):
            continue  # `_scan_js` already judged a handler file
        owners: _JsOwners | None = None
        for found in _js_sinks(text):
            for name, quoting, mode, template in found.interps:
                if owners is None:
                    owners = _JsOwners(text)
                owner = owners.owner(found.pos, name)
                if owner is None:
                    continue
                func, index = owner
                for hrel, handler in readers:
                    hline = handler.tool_arg_call(func, index)
                    if hline is None:
                        continue
                    evidence = (
                        _evidence(func, name, quoting, mode, template)
                        + f"; a tool argument reaches it from another file: "
                        f"{hrel}:{hline} passes it to {func}()"
                    )
                    findings.append(make_finding(INTERP_RULE, rel, evidence, found.line))
                    break
    return findings


# --------------------------------------------------------------------------
# Default-profile reachability
# --------------------------------------------------------------------------
def _default_profile_finding(
    text: str, rel: str, tool_names: list[str], line: int | None
) -> Finding | None:
    """Fire when the command-executing tool has no opt-in gate around it."""
    if _OPT_IN_RE.search(text):
        return None
    shown = ", ".join(sorted(set(tool_names))[:3])
    return make_finding(
        PROFILE_RULE,
        rel,
        (
            f"Command-executing tool(s) ({shown}) are registered in the default "
            "profile with no opt-in flag, env gate, or profile membership; "
            "reachable by any connected MCP client out of the box"
        ),
        line,
    )


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Flag quoted shell interpolation and default-profile reachability."""
    findings: list[Finding] = []
    scanned: set[str] = set()
    js_texts: dict[str, str] = {}

    for path in sorted(project_root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix
        if suffix not in (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"):
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover - unreadable file
            continue

        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        if suffix == ".py":
            found: list[Finding] = []
            exec_tools: list[str] = []
            with refusing_overflow(rel):
                found, exec_tools = _scan_python(text, rel)
        else:
            js_texts[rel] = text
            found, exec_tools = _scan_js(text, rel)

        findings.extend(found)
        if exec_tools:
            profile = _default_profile_finding(
                text, rel, exec_tools, found[0].line_number if found else None
            )
            if profile is not None:
                findings.append(profile)

    # The tool's registration lives in the handler file, so the default-profile
    # qualifier has nothing to read in the sink file and is not attached.
    findings.extend(_cross_file_js(js_texts))
    return findings, scanned
