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
from collections import deque
from collections.abc import Callable, Iterable
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import (
    MatchSpans,
    PatternSpans,
    in_skip_dir,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
)


# A file over this many bytes is not read; the rule's limitation says so. The
# reader below is linear in the file, so the cap bounds the time a crafted file
# can take rather than keeping a quadratic path in check.
_MAX_BYTES = 512_000

# The client gate (`_targets_deepseek`). `OpenAI(... base_url="...deepseek...")`
# was an arm of its own, with `[^)]*` between the call and `base_url`, which read
# to the next `)` from every `OpenAI(`: a file of `OpenAI(` with no `)` took
# 5.6 s at 280 KB, before any other check. The `base_url=` arm matches inside
# every such call, so the gate passes the same files without it.
_BASE_URL_RE = re.compile(r"""base_url\s*=\s*['"]""")
_QUOTE_RE = re.compile(r"""['"]""")
_DEEPSEEK_IMPORT_RE = re.compile(r"from\s+deepseek|import\s+deepseek")
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


def _targets_deepseek(text: str) -> bool:
    """Whether the file names a DeepSeek client: a `base_url=` string holding
    `deepseek`, or an import from a `deepseek` package.

    The `base_url=` arm was `base_url\\s*=\\s*['"][^'"]*deepseek[^'"]*['"]`,
    which tried every `deepseek` in a value never closed and read to the end of
    the file from each: `base_url='` and 63,000 of them took 333.8 s at 504 KB.
    Each value is read to its closing quote once now. A `base_url=` match ends at
    the quote that opens its value, so a value ends at or before the next
    match's quote, and no character is read twice.
    """
    if _DEEPSEEK_IMPORT_RE.search(text):
        return True
    for opened in _BASE_URL_RE.finditer(text):
        closed = _QUOTE_RE.search(text, opened.end())
        if closed is None:
            return False
        if text.find("deepseek", opened.end(), closed.start()) != -1:
            return True
    return False


def _routes(node: ast.expr, lookup: Callable[[str], bool | None]) -> bool | None:
    """Whether a pattern written out names the routing tokens: a string literal,
    a name bound to one, or `re.compile(...)` of either. None for any other
    expression.

    A name holds this answer, decided once where it is bound. It held the
    pattern's text, searched again at every substitution through the name, so a
    256,000-character pattern used by 8,000 calls took 82 s at 424 KB.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _ROUTING_WORD_RE.search(node.value) is not None
    if isinstance(node, ast.Name):
        return lookup(node.id)
    if isinstance(node, ast.Call) and _dotted(node.func) == "re.compile" and node.args:
        return _routes(node.args[0], lookup)
    return None


def _simple_binding(node: ast.AST) -> tuple[str, ast.expr] | None:
    """The name and value of `name = value` or `name: T = value`, else None."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    return None


def _bind(statements: list[ast.stmt], patterns: dict[str, bool], lookup: Callable[[str], bool | None]) -> None:
    """Record in `patterns` each name `statements` bind to a written-out pattern.

    They are read in source order. In the order a breadth-first walk met them,
    `P = R` below an `if` block binding `R` was read before `R` was bound, so a
    substitution through `P` did not count.
    """
    for stmt in sorted(statements, key=lambda s: (s.lineno, s.col_offset)):
        bound = _simple_binding(stmt)
        if bound is not None:
            verdict = _routes(bound[1], lookup)
            if verdict is not None:
                patterns[bound[0]] = verdict


def _module_patterns(tree: ast.Module) -> dict[str, bool]:
    """Every name a module-level assignment binds to a written-out pattern, with
    whether it names the routing tokens. An assignment in a module-level block
    (`if`, `try`, `with`, a loop) counts too; one in a function or a class does
    not. Only the module's own statements used to be read."""
    statements: list[ast.stmt] = []
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            statements.append(node)
        stack.extend(ast.iter_child_nodes(node))
    patterns: dict[str, bool] = {}
    _bind(statements, patterns, patterns.get)
    return patterns


def _sub_routes(call: ast.Call, lookup: Callable[[str], bool | None]) -> bool | None:
    """For `re.sub` / `re.subn`, or `.sub` / `.subn` on a compiled pattern held
    by a name or compiled in place (`re.compile(...).sub(...)`), whether the
    pattern names the routing tokens; None for any other call. A pattern
    compiled in place used not to be read."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr in ("sub", "subn")):
        return None
    receiver = func.value
    if isinstance(receiver, ast.Name) and receiver.id == "re":
        arg = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "pattern"), None)
        return _routes(arg, lookup) if arg is not None else None
    if isinstance(receiver, ast.Name) or (isinstance(receiver, ast.Call) and _dotted(receiver.func) == "re.compile"):
        return _routes(receiver, lookup)
    return None


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
    pattern, with whether it names the routing tokens; `cleaned` the names this
    scope binds that an assignment here, or in a nested function through
    `nonlocal`, gives a routing substitution; `bound` every name the body binds
    (`_names_bound`). A name is the variable of the nearest scope that binds it,
    this one first, then the functions around it, then (for a pattern) the
    module, as Python resolves it (`binder`). `sanitised` and `described` hold
    what `_read` found, judged once every scope is read.
    """

    __slots__ = ("parent", "patterns", "cleaned", "bound", "nonlocals", "sanitised", "described", "cleared")

    def __init__(self, parent: _Scope | None) -> None:
        self.parent = parent
        self.patterns: dict[str, bool] = {}
        self.cleaned: set[str] = set()
        self.bound: set[str] = set()
        self.nonlocals: set[str] = set()
        self.sanitised = False
        self.described: set[str] = set()
        self.cleared = False

    def chain(self) -> Iterable[_Scope]:
        scope: _Scope | None = self
        while scope is not None:
            yield scope
            scope = scope.parent

    def binder(self, name: str) -> _Scope | None:
        """The scope whose variable `name` is, read here: the nearest, this one
        first, that binds the name itself (a `nonlocal` declaration passes it on
        to the functions around), or None for a name no function binds.

        A described name was looked for in every function around this one, so a
        nested function binding its own `clean`, by an assignment or as a
        parameter, borrowed the outer function's cleaning of another variable.
        """
        for scope in self.chain():
            if name in scope.bound and name not in scope.nonlocals:
                return scope
        return None

    def cleans(self, name: str) -> bool:
        """Whether the variable `name` reads here is assigned a routing substitution."""
        binder = self.binder(name)
        return binder is not None and name in binder.cleaned

    def owner(self, name: str) -> _Scope:
        """The scope whose binding of `name` an assignment here sets: this one,
        or for a `nonlocal` name the nearest function around it that binds the
        name itself. A helper that cleans its caller's name through `nonlocal`
        used to clean a name of its own, so the caller reported."""
        if name in self.nonlocals and self.parent is not None:
            return self.parent.binder(name) or self
        return self


def _names_bound(node: ast.AST) -> list[str]:
    """The names a node binds in the function body it sits in.

    A name stored or deleted, a nested function or class, an exception caught
    `as` a name, an import, a match capture, and a lambda's parameters. The
    names a class body, a comprehension or a lambda binds belong to a scope of
    their own in Python; they count here too, which can only make a name a
    function's own and so leave it uncleaned and reported.
    """
    if isinstance(node, ast.Name):
        return [node.id] if isinstance(node.ctx, (ast.Store, ast.Del)) else []
    if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.ExceptHandler):
        return [node.name] if node.name else []
    if isinstance(node, ast.alias):
        return [] if node.name == "*" else [node.asname or node.name.split(".")[0]]
    if isinstance(node, ast.Lambda):
        args = node.args
        return [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg) if a]
    # Python 3.10's match captures, read by name: the classes do not exist on 3.9.
    kind = type(node).__name__
    if kind in ("MatchAs", "MatchStar", "MatchMapping"):
        name = getattr(node, "rest" if kind == "MatchMapping" else "name", None)
        return [name] if name else []
    return []


def _read(func: ast.FunctionDef | ast.AsyncFunctionDef, scope: _Scope, module_patterns: dict[str, bool]) -> None:
    """Read the function's own body into `scope`: whether it neutralises the
    routing tokens in a description it sends, or which names it would need clean.

    `sanitize_tool_description(...)` counts as a call anywhere in the body, as
    the rule text says. A substitution counts only when it is a call in the
    code, its pattern can be read (a string literal, or a name an assignment
    here, in a function around this one or in the module binds to one, directly
    or through `re.compile`) and names the routing tokens (`route` or `expert`,
    any case), and its result is the description: a description value that
    holds it anywhere inside (`doc + re.sub(...)` included, though `doc` goes
    out raw), or a value holding it assigned (`_assigned_names`) to a name the
    description uses, here or in a function around this one. Whether the
    pattern really removes the tokens is not checked: that would mean running a
    regex the scanned file wrote, which a crafted one could make take forever.

    The body is walked once, breadth first as `ast.walk` goes, stopping at each
    nested function, which is read on its own. Each function used to walk its
    whole subtree four times, nested functions included, and to copy the
    module's pattern table, so 95 nested functions over 9,000 statements took
    14.8 s and many constants with many functions grew with their product.
    """
    def lookup(name: str) -> bool | None:
        # The nearest scope binding the name decides, whether or not it binds a
        # pattern; one that assigns it through `nonlocal` holds its own verdict.
        for s in scope.chain():
            verdict = s.patterns.get(name)
            if verdict is not None:
                return verdict
            if name in s.bound and name not in s.nonlocals:
                return None
        return module_patterns.get(name)

    args = func.args
    scope.bound.update(a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs))
    scope.bound.update(a.arg for a in (args.vararg, args.kwarg) if a is not None)

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
        scope.bound.update(_names_bound(node))
        if isinstance(node, _FUNCTIONS):
            continue
        order.append(node)
        marked = node in in_description
        if isinstance(node, ast.Name):
            if marked:
                described.add(node.id)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
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

    _bind([node for node in order if isinstance(node, (ast.Assign, ast.AnnAssign))], scope.patterns, lookup)
    # A node neutralises when a routing substitution lies inside it: mark each
    # such call and its ancestors, stopping at one marked already.
    neutral: set[ast.AST] = set()
    for node in order:
        if isinstance(node, ast.Call) and _sub_routes(node, lookup):
            cur: ast.AST | None = node
            while cur is not None and cur not in neutral and cur is not func:
                neutral.add(cur)
                cur = parent_of.get(cur)
    for node in order:
        for name, value in _assigned_names(node):
            if value in neutral:
                scope.owner(name).cleaned.add(name)
    scope.sanitised = sanitised or any(value in neutral for value in values)
    scope.described = described


def _cleared(functions: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, int]], module_patterns: dict[str, bool]) -> list[bool]:
    """Per function, whether it or a function nested in it neutralises the routing tokens.

    Every function is read before any is judged, since a function nested in
    another can clean the outer one's name through `nonlocal`. A function's
    source includes the functions nested in it, so one of those that cleans its
    description clears it as well, as the subtree walk did; an `@app.route`
    handler cleaned inside an app factory clears the factory.
    """
    scopes: list[_Scope] = []
    for func, parent in functions:
        scope = _Scope(scopes[parent] if parent >= 0 else None)
        _read(func, scope, module_patterns)
        scopes.append(scope)
    for scope in scopes:
        scope.cleared = scope.sanitised or any(scope.cleans(name) for name in scope.described)
    for index in range(len(functions) - 1, -1, -1):
        parent = functions[index][1]
        if parent >= 0 and scopes[index].cleared:
            scopes[parent].cleared = True
    return [scope.cleared for scope in scopes]


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
    if not _targets_deepseek(text):
        return []
    try:
        tree = parse_python(text, path)
    except SyntaxError:
        return []
    functions = _functions(tree)
    if not functions:
        return []
    cleared = _cleared(functions, _module_patterns(tree))
    # A function's source is its lines joined with newlines, as it was cut out
    # before; the file is split once.
    lines = text.splitlines()
    joined = "\n".join(lines)
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)
    # A function's source used to be joined from its lines and searched again
    # for each function, so every level of a nested function searched the
    # levels inside it once more. Each match is found once per file, and a
    # function's lines hold one as a search of them alone would find it.
    sources = PatternSpans(_SOURCE_RES, joined)
    file_reads = MatchSpans(_file_read_spans(joined))
    tools = MatchSpans(_occurrences(joined, "tools=") + _occurrences(joined, "tools ="))
    described = MatchSpans(_occurrences(joined, "description"))
    findings: list[Finding] = []
    for (func, _), is_cleared in zip(functions, cleared):
        first = max(0, func.lineno - 1)
        last = min(len(lines), func.end_lineno or func.lineno)
        if last <= first:
            continue
        start, end = line_starts[first], line_starts[last] - 1
        if is_cleared or not (sources.within(start, end) or file_reads.within(start, end)):
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
            text = read_text_capped(path, _MAX_BYTES, errors="replace")
        except OSError:
            continue
        with refusing_overflow(path):
            findings.extend(_walk_python(text, path, project_root, scanned))
    return findings, scanned
