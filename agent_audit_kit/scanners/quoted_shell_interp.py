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
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, make_finding
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

# A `${...}` interpolation inside a template literal.
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
    func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str, text: str
) -> tuple[list[Finding], bool]:
    """Returns (findings, reached_a_command_sink)."""
    params = _get_param_names(func)
    if not params:
        return [], False

    body_src = ast.get_source_segment(text, func) or ""
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
                    template = ast.get_source_segment(text, value) or ""
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
                template = _shell_template(expr) or ast.get_source_segment(text, expr) or ""
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


def _evidence(func_name: str, param: str, quoting: str, mode: str, template: str) -> str:
    snippet = " ".join(template.split())[:110]
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
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_tool_function(node):
            continue
        found, reached = _analyse_py_function(node, rel, text)
        findings.extend(found)
        if found and reached:
            exec_tools.append(node.name)
    return findings, exec_tools


# --------------------------------------------------------------------------
# TypeScript / JavaScript
# --------------------------------------------------------------------------
def _template_literals(text: str, start: int) -> str | None:
    """Extract the backtick template literal that starts at/after ``start``."""
    open_idx = text.find("`", start)
    if open_idx < 0:
        return None
    # Bail if a statement boundary intervenes — the literal belongs elsewhere.
    if ";" in text[start:open_idx] or "\n\n" in text[start:open_idx]:
        return None
    close_idx = text.find("`", open_idx + 1)
    if close_idx < 0:
        return None
    return text[open_idx + 1 : close_idx]


# A shell sink whose command is a bare identifier: `exec(cmd, ...)`.
_JS_FIRST_IDENT_RE = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*[,)]")

# How far back an assignment to that identifier is looked for.
_JS_LOCAL_WINDOW_LINES = 60


def _js_assigned_templates(text: str, ident: str, before: int) -> list[str]:
    """Template literals assigned to ``ident`` shortly before a sink.

    Every branch counts: nexus-mcp assigns ``cmd`` a different template per
    platform and then runs whichever was taken.
    """
    start = before
    for _ in range(_JS_LOCAL_WINDOW_LINES):
        prev = text.rfind("\n", 0, start - 1)
        if prev < 0:
            start = 0
            break
        start = prev
    assign_re = re.compile(
        rf"(?<![\w$.]){re.escape(ident)}\s*(?::\s*[\w$<>\[\]|, ]+)?\s*=(?![=>])\s*`"
    )
    templates: list[str] = []
    for m in assign_re.finditer(text, start, before):
        template = _template_literals(text, m.end() - 1)
        if template is not None:
            templates.append(template)
    return templates


class _JsSink:
    """One shell sink and the interpolations its command carries."""

    __slots__ = ("sink", "pos", "line", "interps")

    def __init__(self, sink: str, pos: int, line: int, interps: list[tuple[str, str, str, str]]) -> None:
        self.sink = sink
        self.pos = pos
        self.line = line
        # (root name, quoting, mode, template)
        self.interps = interps


def _js_sinks(text: str) -> list[_JsSink]:
    """Every shell sink with an interpolated command, inline or through a local."""
    sinks: list[_JsSink] = []
    for match in _JS_SHELL_SINK_RE.finditer(text):
        sink = match.group(0).rstrip("(").strip()
        call_start = match.end()
        template = _template_literals(text, call_start)

        # `execFile`/`spawn` do not spawn a shell — only interesting when an
        # argv element rides behind an interpreter eval flag.
        if sink not in _JS_SHELL_ONLY:
            window = text[call_start : call_start + 400]
            if not any(f'"{f}"' in window or f"'{f}'" in window for f in _EVAL_FLAGS):
                continue

        templates = [template] if template is not None else []
        if not templates and sink in _JS_SHELL_ONLY:
            ident = _JS_FIRST_IDENT_RE.match(text, call_start)
            if ident:
                templates = _js_assigned_templates(text, ident.group(1), match.start())
        mode = "shell" if sink in _JS_SHELL_ONLY else "argv-eval"
        # One command string can interpolate the same value more than once —
        # CVE-2026-55157 uses `username` twice in one template. That is one
        # defect, not two; so is one value in each branch of a platform switch.
        seen: set[tuple[str, str]] = set()
        interps: list[tuple[str, str, str, str]] = []
        for tpl in templates:
            for expr in _JS_INTERP_RE.findall(tpl):
                quoting = _quote_context(tpl, "${" + expr + "}")
                name = expr.strip().split(".")[-1].split(" ")[0] or "argument"
                if (name, quoting) not in seen:
                    seen.add((name, quoting))
                    interps.append((name, quoting, mode, tpl))
        if interps:
            line = text[: match.start()].count("\n") + 1
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
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:  # pragma: no cover - defensive
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
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
