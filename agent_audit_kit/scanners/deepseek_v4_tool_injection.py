"""AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001 — MoE-routed tool prompt injection.

DeepSeek V4 (Apache 2.0, 2026-04-24) introduces a tool-call envelope
where MoE routing is exposed. Untrusted document text reaching a tool
description can poison routing into a higher-privileged expert. LLM01
class with MoE-specific surface.

Speculative shape per spec — `route_id` envelope behaviour inferred
from V4 release notes. Sanitiser bypass available via
`agent_audit_kit.sanitizers.deepseek.sanitize_tool_description`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import in_skip_dir, make_finding


_DEEPSEEK_HINT_RE = re.compile(
    r"""
    (?:
        OpenAI\s*\([^)]*base_url\s*=\s*['"][^'"]*deepseek[^'"]*['"]
      | base_url\s*=\s*['"][^'"]*deepseek[^'"]*['"]
      | from\s+deepseek
      | import\s+deepseek
    )
    """,
    re.VERBOSE,
)
_TAINT_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|body|args|form|data|values|files)\b
      | \brequest\s*\.\s*get_json
      | \bflask\.request\.\w+
      | \bfastapi\.Request
      | \bawait\s+request\.json\(\)
      | \bpdfplumber\.open
      | \bunstructured\.partition
      | \bUnstructuredFileLoader
      | \bopen\([^)]*\)\.read\(\)
    )
    """,
    re.VERBOSE,
)
# The words in the tokens `sanitize_tool_description` removes: `[ROUTE: ...]`,
# `<|route_id|>`, `__route__=`, `{{expert: ...}}`.
_ROUTING_WORD_RE = re.compile(r"route|expert", re.IGNORECASE)


def _dotted(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _pattern_text(node: ast.expr, known: dict[str, str]) -> str | None:
    """The regex a pattern expression spells when it is written out: a string
    literal, a name bound to one, or `re.compile(...)` of either."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return known.get(node.id)
    if isinstance(node, ast.Call) and _dotted(node.func) == "re.compile" and node.args:
        return _pattern_text(node.args[0], known)
    return None


def _pattern_bindings(stmts: list[ast.stmt], known: dict[str, str]) -> dict[str, str]:
    """`known` plus every name a simple assignment in `stmts` binds to a written-out pattern."""
    out = dict(known)
    for stmt in stmts:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            name, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            name, value = stmt.target.id, stmt.value
        else:
            continue
        text = _pattern_text(value, out)
        if text is not None:
            out[name] = text
    return out


def _sub_pattern(call: ast.Call, known: dict[str, str]) -> str | None:
    """The pattern of `re.sub` / `re.subn`, or of `.sub` / `.subn` on a compiled pattern held by name."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr in ("sub", "subn") and isinstance(func.value, ast.Name)):
        return None
    if func.value.id != "re":
        return known.get(func.value.id)
    arg = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "pattern"), None)
    return _pattern_text(arg, known) if arg is not None else None


def _description_values(func: ast.AST) -> list[ast.expr]:
    """What the function sends as a description: a `"description"` dict value, a
    `description=` argument, or a `x["description"] = ...` assignment."""
    values: list[ast.expr] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Dict):
            values += [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value == "description"]
        elif isinstance(node, ast.Call):
            values += [kw.value for kw in node.keywords if kw.arg == "description"]
        elif isinstance(node, ast.Assign):
            values += [
                node.value for t in node.targets
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == "description"
            ]
    return values


def _sanitises_description(func: ast.AST, module_patterns: dict[str, str]) -> bool:
    """Whether the function neutralises the routing tokens in the description it sends.

    `sanitize_tool_description(...)` counts as a call anywhere in the function,
    as the rule text says. A substitution counts only when it is a call in the
    code, its pattern can be read (a string literal, or a name a module- or
    function-level assignment binds to one, directly or through `re.compile`)
    and names the routing tokens (`route` or `expert`, any case), and its
    result is the description: the description value itself, or assigned to a
    name the description uses. The function body used to be read as text, so
    any `re.sub(` counted, then a literal pattern naming the tokens did, which
    still let a commented-out line or a substitution on another variable
    (`path = re.sub(r"/route/", "/", path)`) pass and missed a pattern kept in a
    module constant (`re.sub(ROUTE_TOKEN_RE, "", doc)`). Whether the pattern
    really removes the tokens is not checked: that would mean running a regex
    the scanned file wrote, which a crafted one could make take forever.
    """
    calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)]
    if any(_dotted(c.func).rsplit(".", 1)[-1] == "sanitize_tool_description" for c in calls):
        return True
    known = _pattern_bindings(
        [n for n in ast.walk(func) if isinstance(n, (ast.Assign, ast.AnnAssign))], module_patterns
    )

    def neutralises(expr: ast.expr) -> bool:
        return any(
            isinstance(n, ast.Call) and _ROUTING_WORD_RE.search(_sub_pattern(n, known) or "") is not None
            for n in ast.walk(expr)
        )

    values = _description_values(func)
    if any(neutralises(v) for v in values):
        return True
    names = {n.id for v in values for n in ast.walk(v) if isinstance(n, ast.Name)}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id in names for t in targets) and neutralises(value):
            return True
    return False


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _DEEPSEEK_HINT_RE.search(text):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    module_patterns = _pattern_bindings(tree.body, {})
    # Split once per file: each function used to split the whole text again to
    # cut out its own lines, so 20,000 functions took 26 s.
    lines = text.splitlines()
    findings: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def _scan(self, func: ast.AST) -> None:
            start = max(0, func.lineno - 1)  # type: ignore[attr-defined]
            end_lineno = getattr(func, "end_lineno", func.lineno) or func.lineno  # type: ignore[attr-defined]
            end = min(len(lines), end_lineno)
            body = "\n".join(lines[start:end])
            if not _TAINT_RE.search(body):
                return
            if _sanitises_description(func, module_patterns):
                return
            # Look for tools=[{ ... description: <tainted> ... }] passing
            # in an LLM call. Heuristic: presence of `tools=` AND a dict
            # literal with `description` key in the function body.
            if "tools=" not in body and "tools =" not in body:
                return
            if "description" not in body:
                return
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001",
                rel,
                "DeepSeek V4-shaped LLM call passes `tools=[{description: "
                "...}]` in a function that reads from a network / "
                "document source without sanitize_tool_description. "
                "Untrusted text can poison MoE routing.",
                line_number=getattr(func, "lineno", 1),
            ))

    V().visit(tree)
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if in_skip_dir(path, project_root):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_walk_python(text, path, project_root, scanned))
    return findings, scanned
