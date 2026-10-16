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

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import in_skip_dir, make_finding
from agent_audit_kit.scanners.taint_analysis import (
    _get_param_names,
    _is_tool_function,
    _resolve_callee,
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


# A source line as `ast.get_source_segment` splits them: up to `\r\n`, `\n` or `\r`.
_PY_LINE_RE = re.compile(r".*?(?:\r\n|\n|\r|$)")


class _PySource:
    """`ast.get_source_segment` for many nodes of one file, its lines split once.

    `get_source_segment` splits the whole source into lines on every call, and
    this scanner asks it for every tool function and for every template it
    cannot rebuild: 227 KB of tool functions took 7.6 seconds, growing with the
    square of the file. The lines are split where it splits them, and a segment
    is cut from them the way it cuts one, from each line encoded once.
    """

    def __init__(self, text: str) -> None:
        self._lines = [m.group() for m in _PY_LINE_RE.finditer(text)]
        self._encoded: dict[int, bytes] = {}

    def _line(self, i: int) -> bytes:
        line = self._encoded.get(i)
        if line is None:
            line = self._encoded[i] = self._lines[i].encode()
        return line

    def segment(self, node: ast.AST) -> str | None:
        lineno, end_lineno = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        col, end_col = getattr(node, "col_offset", None), getattr(node, "end_col_offset", None)
        if lineno is None or end_lineno is None or col is None or end_col is None:
            return None
        first, last = lineno - 1, end_lineno - 1
        if first == last:
            return self._line(first)[col:end_col].decode()
        return (
            self._line(first)[col:].decode()
            + "".join(self._lines[first + 1 : last])
            + self._line(last)[:end_col].decode()
        )


def _analyse_py_function(
    func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str, source: _PySource
) -> tuple[list[Finding], bool]:
    """Returns (findings, reached_a_command_sink)."""
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
        callee = _resolve_callee(node)
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
        tree = ast.parse(text)
    except SyntaxError:
        return [], []
    findings: list[Finding] = []
    exec_tools: list[str] = []
    source = _PySource(text)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_tool_function(node):
            continue
        found, reached = _analyse_py_function(node, rel, source)
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

_BACKTICK_RE = re.compile("`")
_SEMICOLON_RE = re.compile(";")
_BLANK_LINE_RE = re.compile(r"(?=\n\n)")
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
    second). Each of those is now a lookup in positions found once, and a
    template's interpolations are read once however many sinks run it.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._ticks = _positions(text, _BACKTICK_RE)
        self._semicolons = _positions(text, _SEMICOLON_RE)
        self._blank_lines = _positions(text, _BLANK_LINE_RE)
        self._newlines = _positions(text, _NEWLINE_RE)
        self._templates: dict[int, tuple[str, list[tuple[str, str]]]] = {}
        self._assignments: dict[str, _JsAssignments] | None = None

    def template_at(self, start: int) -> tuple[str, list[tuple[str, str]]] | None:
        """The backtick template literal that starts at or after ``start``, and
        its interpolations, or None when there is none or a `;` or blank line
        comes before it (the literal belongs to another statement)."""
        i = bisect_left(self._ticks, start)
        if i + 1 >= len(self._ticks):
            return None  # no opening backtick, or none to close it
        opening = self._ticks[i]
        if _first_at(self._semicolons, start) < opening or _first_at(self._blank_lines, start) + 2 <= opening:
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
            self._assignments = _js_template_assignments(self.text)
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


def _js_template_assignments(text: str) -> dict[str, _JsAssignments]:
    """Every assignment of a template literal to a name, by name.

    A name the sink reads, assigned with `(?<![\\w$.])name` + `_JS_TYPED_ASSIGN`
    + a backtick, is a whole run of name characters: the lookbehind starts it
    and the type or `=` after it ends it. So each run that starts a name is
    tried once, for whatever name it is.
    """
    out: dict[str, _JsAssignments] = {}
    for m in _JS_ASSIGNABLE_RE.finditer(text):
        tail = _JS_TEMPLATE_ASSIGN_RE.match(text, m.end())
        if tail:
            sites = out.get(m.group())
            if sites is None:
                sites = out[m.group()] = _JsAssignments()
            sites.starts.append(m.start())
            sites.ends.append(tail.end())
            sites.ticks.append(tail.end() - 1)
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
    js = _JsFile(text)
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

# A function or method header whose body opens with `{`.
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


def _js_enclosing_param(text: str, pos: int, name: str) -> tuple[str, int] | None:
    """The nearest enclosing function that takes ``name`` as a parameter."""
    headers = [m for m in _JS_HEADER_RE.finditer(text, 0, pos)]
    for m in reversed(headers):
        func = m.group("fname") or m.group("mname") or m.group("aname") or ""
        if func in _JS_KEYWORDS:
            continue
        body = text.find("{", m.end())
        if body < 0 or body >= pos:
            continue
        segment = text[body + 1 : pos]
        if 1 + segment.count("{") - segment.count("}") <= 0:
            continue  # the body closed before the sink: not enclosing
        params = _js_param_names(m.group("fparams") or m.group("mparams") or m.group("aparams") or "")
        if name in params and func:
            return func, params.index(name)
    return None


def _strip_subscripts(expr: str) -> str:
    """`TABLE[key]` is the table's value, not the key: drop what indexes it."""
    prev = None
    while prev != expr:
        prev = expr
        expr = re.sub(r"\[[^\[\]]*\]", "", expr)
    return expr


def _js_tool_derived_names(text: str) -> set[str]:
    """Locals a handler file assigns from a tool argument, to a fixed point."""
    assigns: list[tuple[list[str], str]] = []
    for m in re.finditer(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])\s*([^;\n]+)", text
    ):
        assigns.append(([m.group(1)], m.group(2)))
    for m in re.finditer(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=;\n]+)?=\s*([^;\n]+)", text):
        bound = []
        for part in _split_top_level(m.group(1)):
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
            if _js_is_tool_derived(rhs, tainted, destructure=len(names) > 1 or rhs.strip() in {"args", "input"}):
                tainted.update(names)
                changed = True
    return tainted


def _js_is_tool_derived(expr: str, tainted: set[str], destructure: bool = False) -> bool:
    bare = _strip_subscripts(expr)
    if _JS_TOOL_ARG_RE.search(bare):
        return True
    if destructure and re.search(r"\b(?:args|arguments|input)\b", bare):
        return True
    return any(re.search(rf"(?<![\w$.]){re.escape(n)}(?![\w$])", bare) for n in tainted)


def _js_call_args(text: str, open_paren: int) -> list[str]:
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return _split_top_level(text[open_paren + 1 : i], brackets="([{")
    return []


def _js_tool_arg_call(text: str, func: str, index: int) -> int | None:
    """Line of a call to ``func`` whose argument at ``index`` is tool-derived."""
    tainted = _js_tool_derived_names(text)
    call_re = re.compile(rf"(?<![\w$]){re.escape(func)}\s*\(")
    for m in call_re.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        head = text[line_start : m.start()]
        if re.search(r"\bfunction\s*$|^\s*(?:(?:public|private|protected|static|async)\s+)*$", head):
            continue  # a definition, not a call
        args = _js_call_args(text, m.end() - 1)
        if index < len(args) and _js_is_tool_derived(args[index], tainted):
            return text[: m.start()].count("\n") + 1
    return None


def _cross_file_js(texts: dict[str, str]) -> list[Finding]:
    handlers = {rel: t for rel, t in texts.items() if _JS_TOOL_ARG_RE.search(t)}
    findings: list[Finding] = []
    for rel, text in texts.items():
        if rel in handlers or _JS_QUOTE_RE.search(text):
            continue  # `_scan_js` already judged a handler file
        for found in _js_sinks(text):
            for name, quoting, mode, template in found.interps:
                owner = _js_enclosing_param(text, found.pos, name)
                if owner is None:
                    continue
                func, index = owner
                for hrel, htext in sorted(handlers.items()):
                    hline = _js_tool_arg_call(htext, func, index)
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
