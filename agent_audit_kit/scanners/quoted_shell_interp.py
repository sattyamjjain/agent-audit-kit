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


def _scan_js(text: str, rel: str) -> tuple[list[Finding], list[str]]:
    if _JS_QUOTE_RE.search(text):
        return [], []
    if not _JS_TOOL_ARG_RE.search(text):
        return [], []

    findings: list[Finding] = []
    exec_tools: list[str] = []

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

        if template is None:
            continue
        interps = _JS_INTERP_RE.findall(template)
        if not interps:
            continue

        line = text[: match.start()].count("\n") + 1
        # One command string can interpolate the same value more than once —
        # CVE-2026-55157 uses `username` twice in one template. That is one
        # defect, not two.
        seen: set[tuple[str, str]] = set()
        for expr in interps:
            marker = "${" + expr + "}"
            quoting = _quote_context(template, marker)
            name = expr.strip().split(".")[-1].split(" ")[0] or "argument"
            if (name, quoting) in seen:
                continue
            seen.add((name, quoting))
            mode = "shell" if sink in _JS_SHELL_ONLY else "argv-eval"
            findings.append(
                make_finding(
                    INTERP_RULE,
                    rel,
                    _evidence(sink, name, quoting, mode, template),
                    line,
                )
            )
            exec_tools.append(sink)

    return findings, exec_tools


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
    evaluated = {INTERP_RULE, PROFILE_RULE}

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
        if suffix == ".py":
            found, exec_tools = _scan_python(text, rel)
        else:
            found, exec_tools = _scan_js(text, rel)

        findings.extend(found)
        if exec_tools:
            profile = _default_profile_finding(
                text, rel, exec_tools, found[0].line_number if found else None
            )
            if profile is not None:
                findings.append(profile)

    return findings, evaluated
