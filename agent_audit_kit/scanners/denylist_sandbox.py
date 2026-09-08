"""AAK-SANDBOX-DENYLIST-001 — a deny-list of names used as a sandbox boundary.

The detector #656 was deferred for, split out as #704 and built here.

CVE-2026-81096 (ToolUniverse, CVSS 10.0) is the exemplar. Its
`python_code_executor` inspects submitted source against a denied list of
attribute names and calls, but leaves the attribute-lookup builtins available, so
a caller reaches a dunder through a string lookup — or through a module already
permitted — and walks `literal.__class__.__base__.__subclasses__()` until it
holds `subprocess`. CVE-2026-53710 (RestrictedPython `getattr` bypass in
mcp-context-forge) is the same shape in a different product, which is what makes
this a class rather than a one-off.

The stated blocker on #656 was that a detector has to tell a deny-list sandbox
from a real one *without firing on every codebase that mentions `eval`*. A
pattern that flags `exec(` is noise. The distinguishing feature is the
combination, and all four parts are required:

  1. a deny-list of **names**, held as string literals, drawn from the vocabulary
     that only appears when someone is trying to stop a sandbox escape;
  2. that list is **checked against a value** — membership, substring scan or
     regex — rather than merely defined;
  3. an **exec-family call** in the same module, so the checked source is
     actually run in-process;
  4. the **attribute-lookup builtins are still reachable** — `getattr`,
     `__getattribute__`, `vars`, `globals` are absent from the list, or handed
     into the execution namespace explicitly.

Point 4 is what makes this a defect rather than a design choice: a deny-list that
also denies the lookup primitives is merely fragile, while one that leaves them
reachable is bypassable by construction.

Two suppressions, both from #704's acceptance list. An **allow-list** in the same
module (`ALLOWED_*`, `WHITELIST`, `PERMITTED_*`) means the deny-list is
defence-in-depth on top of a real boundary, not the boundary itself. And a
**subprocess-isolated** executor never satisfies (3), because the submitted
source is handed to another process rather than exec'd here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding

RULE_ID = "AAK-SANDBOX-DENYLIST-001"

# Names that only end up in a string collection when someone is trying to stop a
# sandbox escape. Ordinary configuration does not list `__subclasses__`.
_DENY_VOCAB = frozenset({
    "__class__", "__bases__", "__base__", "__subclasses__", "__globals__",
    "__mro__", "__builtins__", "__import__", "__code__", "__closure__",
    "__dict__", "__getattribute__", "__reduce__", "__init_subclass__",
    "eval", "exec", "compile", "open", "input", "breakpoint",
    "os", "sys", "subprocess", "importlib", "socket", "shutil", "ctypes",
    "globals", "locals", "vars", "getattr", "setattr", "delattr", "dir",
})
# The lookup primitives. If these are still reachable, the deny-list is
# bypassable by construction -- that is the whole finding.
_LOOKUP_PRIMITIVES = frozenset({
    "getattr", "__getattribute__", "vars", "globals", "dir", "eval",
})
_MIN_DENY_HITS = 3

_EXEC_CALLEES = frozenset({"exec", "eval", "compile", "compile_restricted"})
_ALLOWLIST_TOKENS = ("allowed", "allowlist", "whitelist", "permitted", "safe_builtins")
_CHECK_CALLEES = frozenset({"search", "match", "findall", "find", "index", "startswith"})


def _string_items(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        return []
    return [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]


def _denylists(tree: ast.AST) -> dict[str, set[str]]:
    """Module-level or local collections of dangerous *names*, by variable name."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None:
            continue
        # frozenset({...}) / set([...]) wrappers
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
                and value.func.id in ("frozenset", "set", "list", "tuple") and value.args:
            value = value.args[0]
        items = _string_items(value)
        if not items:
            continue
        hits = {i for i in items if i in _DENY_VOCAB}
        if len(hits) < _MIN_DENY_HITS:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            if isinstance(t, ast.Name):
                out[t.id] = set(items)
    return out


def _has_allowlist(tree: ast.AST, text: str) -> bool:
    low = text.lower()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and any(t in node.id.lower() for t in _ALLOWLIST_TOKENS):
            return True
    return "safe_builtins" in low


def _denylist_is_checked(tree: ast.AST, names: set[str]) -> bool:
    """The list is compared against something, not merely defined."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.In, ast.NotIn)):
                    for side in [node.left] + list(node.comparators):
                        for sub in ast.walk(side):
                            if isinstance(sub, ast.Name) and sub.id in names:
                                return True
        if isinstance(node, ast.Call):
            f = node.func
            attr = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
            if attr in _CHECK_CALLEES or attr in ("any", "all"):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and sub.id in names:
                        return True
        # for token in DENIED: ...
        if isinstance(node, ast.For):
            for sub in ast.walk(node.iter):
                if isinstance(sub, ast.Name) and sub.id in names:
                    return True
    return False


def _exec_calls(tree: ast.AST) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in _EXEC_CALLEES and node.args:
                # exec on a literal is not a sandbox; it needs a variable source.
                if not (len(node.args) == 1 and isinstance(node.args[0], ast.Constant)):
                    out.append(node)
    return out


def _reachable_primitives(denied: set[str], text: str) -> set[str]:
    """Lookup primitives the deny-list does not deny."""
    reachable = {p for p in _LOOKUP_PRIMITIVES if p not in denied}
    # A namespace that hands `getattr` in explicitly is reachable even if denied.
    for p in _LOOKUP_PRIMITIVES:
        if f'"{p}": {p}' in text or f"'{p}': {p}" in text:
            reachable.add(p)
    return reachable


def _analyze(text: str, rel: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    lists = _denylists(tree)
    if not lists:
        return []
    execs = _exec_calls(tree)
    if not execs:
        return []
    if _has_allowlist(tree, text):
        return []

    findings: list[Finding] = []
    for var, denied in lists.items():
        if not _denylist_is_checked(tree, {var}):
            continue
        reachable = _reachable_primitives(denied, text)
        if not reachable:
            continue
        shown = ", ".join(f"`{p}`" for p in sorted(reachable)[:4])
        findings.append(make_finding(
            RULE_ID,
            rel,
            f"`{var}` denies {len(denied)} names by string and is checked against "
            f"submitted source, which is then run in-process by "
            f"`{_callee_name(execs[0])}()` — but {shown} "
            f"{'remains' if len(reachable) == 1 else 'remain'} reachable, so a caller "
            f"reaches a denied attribute through a lookup instead of by name. This is "
            f"the CVE-2026-81096 shape.",
            execs[0].lineno,
        ))
    return findings


def _callee_name(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "exec")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        hits = _analyze(text, rel)
        if hits:
            findings.extend(hits)
            scanned.add(rel)
    return findings, scanned
