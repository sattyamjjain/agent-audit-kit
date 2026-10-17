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
import bisect
import re
from collections import deque
from collections.abc import Callable, Iterable
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
# The untrusted sources, one pattern each so that every match of each is found:
# a function's source holds one when a match lies wholly inside it.
# `open(...).read()` is read apart, by `_file_read_spans`.
_SOURCE_RES = tuple(
    re.compile(pattern)
    for pattern in (
        r"\brequest\.(?:json|body|args|form|data|values|files)\b",
        r"\brequest\s*\.\s*get_json",
        r"\bflask\.request\.\w+",
        r"\bfastapi\.Request",
        r"\bawait\s+request\.json\(\)",
        r"\bpdfplumber\.open",
        r"\bunstructured\.partition",
        r"\bUnstructuredFileLoader",
    )
)
_OPEN_RE = re.compile(r"\bopen\(")
_READ_AFTER = ").read()"
# The words in the tokens `sanitize_tool_description` removes: `[ROUTE: ...]`,
# `<|route_id|>`, `__route__=`, `{{expert: ...}}`.
_ROUTING_WORD_RE = re.compile(r"route|expert", re.IGNORECASE)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _dotted(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _pattern_text(node: ast.expr, lookup: Callable[[str], str | None]) -> str | None:
    """The regex a pattern expression spells when it is written out: a string
    literal, a name bound to one, or `re.compile(...)` of either."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return lookup(node.id)
    if isinstance(node, ast.Call) and _dotted(node.func) == "re.compile" and node.args:
        return _pattern_text(node.args[0], lookup)
    return None


def _simple_binding(node: ast.AST) -> tuple[str, ast.expr] | None:
    """The name and value of `name = value` or `name: T = value`, else None."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    return None


def _module_patterns(body: list[ast.stmt]) -> dict[str, str]:
    """Every name a module-level statement binds to a written-out pattern."""
    patterns: dict[str, str] = {}
    for stmt in body:
        bound = _simple_binding(stmt)
        if bound is not None:
            text = _pattern_text(bound[1], patterns.get)
            if text is not None:
                patterns[bound[0]] = text
    return patterns


def _sub_pattern(call: ast.Call, lookup: Callable[[str], str | None]) -> str | None:
    """The pattern of `re.sub` / `re.subn`, or of `.sub` / `.subn` on a compiled pattern held by name."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr in ("sub", "subn") and isinstance(func.value, ast.Name)):
        return None
    if func.value.id != "re":
        return lookup(func.value.id)
    arg = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "pattern"), None)
    return _pattern_text(arg, lookup) if arg is not None else None


def _assigned_names(node: ast.AST) -> list[tuple[str, ast.expr]]:
    """The names a statement or expression assigns, each with the value it gets.

    `name = value`, `name: T = value`, `name += value` and `(name := value)`
    give the name its value; unpacking gives each name the matching item of a
    tuple written out, and gives the first name all of a `subn(...)` call, whose
    first item is the new string (`clean, n = re.subn(...)`). Only `=` and an
    annotated `=` used to count, so the other three left a cleaned description
    reported.
    """
    if isinstance(node, ast.Assign):
        targets, value = node.targets, node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        targets, value = [node.target], node.value
    elif isinstance(node, ast.NamedExpr):
        targets, value = [node.target], node.value
    elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
        targets, value = [node.target], node.value
    else:
        return []
    out: list[tuple[str, ast.expr]] = []
    for target in targets:
        if isinstance(target, ast.Name):
            out.append((target.id, value))
        elif isinstance(target, (ast.Tuple, ast.List)) and target.elts:
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
                out += [(t.id, v) for t, v in zip(target.elts, value.elts) if isinstance(t, ast.Name)]
            elif (
                isinstance(target.elts[0], ast.Name)
                and isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "subn"
            ):
                out.append((target.elts[0].id, value))
    return out


def _functions(tree: ast.Module) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, int]]:
    """Every function, in the order a recursive visitor meets them, each with the
    index of the function it is nested in (-1 for none). An explicit stack, so a
    deeply nested expression cannot exhaust the recursion limit here."""
    found: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, int]] = []
    stack: list[tuple[ast.AST, int]] = [(child, -1) for child in reversed(list(ast.iter_child_nodes(tree)))]
    while stack:
        node, parent = stack.pop()
        if isinstance(node, _FUNCTIONS):
            found.append((node, parent))
            parent = len(found) - 1
        stack.extend((child, parent) for child in reversed(list(ast.iter_child_nodes(node))))
    return found


class _Scope:
    """One function's own body, the functions nested in it left out.

    `patterns` holds the names an assignment here binds to a written-out
    pattern, `cleaned` the names assigned here from a routing substitution. A
    name is looked up here, then in the functions around this one, then (for a
    pattern) in the module, as Python resolves it.
    """

    __slots__ = ("parent", "patterns", "cleaned", "cleared")

    def __init__(self, parent: _Scope | None) -> None:
        self.parent = parent
        self.patterns: dict[str, str] = {}
        self.cleaned: set[str] = set()
        self.cleared = False

    def chain(self) -> Iterable[_Scope]:
        scope: _Scope | None = self
        while scope is not None:
            yield scope
            scope = scope.parent


def _judge(func: ast.FunctionDef | ast.AsyncFunctionDef, scope: _Scope, module_patterns: dict[str, str]) -> bool:
    """Whether the function's own body neutralises the routing tokens in a description it sends.

    `sanitize_tool_description(...)` counts as a call anywhere in the body, as
    the rule text says. A substitution counts only when it is a call in the
    code, its pattern can be read (a string literal, or a name an assignment
    here, in a function around this one or in the module binds to one, directly
    or through `re.compile`) and names the routing tokens (`route` or `expert`,
    any case), and its result is the description: the description value itself,
    or assigned (`_assigned_names`) to a name the description uses, here or in a
    function around this one. Whether the pattern really removes the tokens is
    not checked: that would mean running a regex the scanned file wrote, which a
    crafted one could make take forever.

    The body is walked once, breadth first as `ast.walk` goes, stopping at each
    nested function, which is judged on its own. Each function used to walk its
    whole subtree four times, nested functions included, and to copy the
    module's pattern table, so 95 nested functions over 9,000 statements took
    14.8 s and many constants with many functions grew with their product.
    """
    def lookup(name: str) -> str | None:
        for s in scope.chain():
            text = s.patterns.get(name)
            if text is not None:
                return text
        return module_patterns.get(name)

    order: list[ast.AST] = []
    parent_of: dict[ast.AST, ast.AST] = {}
    in_description: set[ast.AST] = set()
    described: set[str] = set()
    values: list[ast.expr] = []
    sanitised = False
    queue: deque[ast.AST] = deque()
    for child in ast.iter_child_nodes(func):
        parent_of[child] = func
        queue.append(child)
    while queue:
        node = queue.popleft()
        if isinstance(node, _FUNCTIONS):
            continue
        order.append(node)
        marked = node in in_description
        if isinstance(node, ast.Name):
            if marked:
                described.add(node.id)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "description":
                    values.append(value)
                    in_description.add(value)
        elif isinstance(node, ast.Call):
            if _dotted(node.func).rsplit(".", 1)[-1] == "sanitize_tool_description":
                sanitised = True
            for kw in node.keywords:
                if kw.arg == "description":
                    values.append(kw.value)
                    in_description.add(kw.value)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "description"
                ):
                    values.append(node.value)
                    in_description.add(node.value)
        for child in ast.iter_child_nodes(node):
            parent_of[child] = node
            if marked:
                in_description.add(child)
            queue.append(child)

    for node in order:
        bound = _simple_binding(node)
        if bound is not None:
            text = _pattern_text(bound[1], lookup)
            if text is not None:
                scope.patterns[bound[0]] = text
    # A node neutralises when a routing substitution lies inside it: mark each
    # such call and its ancestors, stopping at one marked already.
    neutral: set[ast.AST] = set()
    for node in order:
        if isinstance(node, ast.Call) and _ROUTING_WORD_RE.search(_sub_pattern(node, lookup) or ""):
            cur: ast.AST | None = node
            while cur is not None and cur not in neutral and cur is not func:
                neutral.add(cur)
                cur = parent_of.get(cur)
    for node in order:
        for name, value in _assigned_names(node):
            if value in neutral:
                scope.cleaned.add(name)
    if sanitised or any(value in neutral for value in values):
        return True
    return any(name in s.cleaned for name in described for s in scope.chain())


def _cleared(functions: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, int]], module_patterns: dict[str, str]) -> list[bool]:
    """Per function, whether it or a function nested in it neutralises the routing tokens.

    A function's source includes the functions nested in it, so one of those
    that cleans its description clears it as well, as the subtree walk did; an
    `@app.route` handler cleaned inside an app factory clears the factory.
    """
    scopes: list[_Scope] = []
    for func, parent in functions:
        scope = _Scope(scopes[parent] if parent >= 0 else None)
        scope.cleared = _judge(func, scope, module_patterns)
        scopes.append(scope)
    for index in range(len(functions) - 1, -1, -1):
        parent = functions[index][1]
        if parent >= 0 and scopes[index].cleared:
            scopes[parent].cleared = True
    return [scope.cleared for scope in scopes]


class _Spans:
    """Where the matches of a pattern lie in a text, to ask whether a range holds one whole.

    A function's source used to be joined from its lines and searched again for
    each function, so every level of a nested function searched the levels
    inside it once more. Each match is found once per file now, and a range is
    asked about with one binary search: the first match starting in it, and the
    earliest end among the matches from there on.
    """

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        spans.sort()
        self._starts = [start for start, _ in spans]
        ends = [end for _, end in spans]
        for index in range(len(ends) - 2, -1, -1):
            ends[index] = min(ends[index], ends[index + 1])
        self._ends = ends

    def within(self, start: int, end: int) -> bool:
        index = bisect.bisect_left(self._starts, start)
        return index < len(self._starts) and self._ends[index] <= end


def _occurrences(text: str, word: str) -> list[tuple[int, int]]:
    spans = []
    at = text.find(word)
    while at != -1:
        spans.append((at, at + len(word)))
        at = text.find(word, at + 1)
    return spans


def _file_read_spans(text: str) -> list[tuple[int, int]]:
    """Every match of `\\bopen\\([^)]*\\)\\.read\\(\\)` that a range could hold whole.

    As an arm of the source pattern, it read to the next `)` from every `open(`,
    so a function holding 100,000 `open(` and no `)` took quadratic time. Every
    `open(` between two `)` has the same next one, so the match from the last of
    them is the shortest, and lies inside every range any of the others does.
    """
    spans = []
    last_close = -1
    for m in _OPEN_RE.finditer(text):
        if m.start() <= last_close:
            continue
        close = text.find(")", m.end())
        if close == -1:
            break
        # The last `open(` before this `)`, by the same pattern.
        start = m.start()
        while True:
            later = _OPEN_RE.search(text, start + 1, close)
            if later is None:
                break
            start = later.start()
        if text.startswith(_READ_AFTER, close):
            spans.append((start, close + len(_READ_AFTER)))
        last_close = close
    return spans


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _DEEPSEEK_HINT_RE.search(text):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    functions = _functions(tree)
    if not functions:
        return []
    cleared = _cleared(functions, _module_patterns(tree.body))
    # A function's source is its lines joined with newlines, as it was cut out
    # before; the file is split once.
    lines = text.splitlines()
    joined = "\n".join(lines)
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)
    sources = _Spans([m.span() for pattern in _SOURCE_RES for m in pattern.finditer(joined)] + _file_read_spans(joined))
    tools = _Spans(_occurrences(joined, "tools=") + _occurrences(joined, "tools ="))
    described = _Spans(_occurrences(joined, "description"))
    findings: list[Finding] = []
    for (func, _), is_cleared in zip(functions, cleared):
        first = max(0, func.lineno - 1)
        last = min(len(lines), func.end_lineno or func.lineno)
        if last <= first:
            continue
        start, end = line_starts[first], line_starts[last] - 1
        if is_cleared or not sources.within(start, end):
            continue
        # Look for tools=[{ ... description: <tainted> ... }] passing
        # in an LLM call. Heuristic: presence of `tools=` AND a dict
        # literal with `description` key in the function body.
        if not tools.within(start, end) or not described.within(start, end):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001",
            rel,
            "DeepSeek V4-shaped LLM call passes `tools=[{description: "
            "...}]` in a function that reads from a network / "
            "document source without sanitize_tool_description. "
            "Untrusted text can poison MoE routing.",
            line_number=func.lineno,
        ))
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
