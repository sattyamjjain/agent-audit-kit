"""AAK-POLICY-VERDICT-FAILOPEN-001 and AAK-POLICY-IMPORT-FAILOPEN-001: gates that open on the unexpected.

A policy gate holds only if whatever it did not expect ends up refused. Two shapes
break that without anything looking wrong on the happy path.

**A verdict matched against one deny word.** An agent asks a model, a service or a
hook for a verdict, blocks when it equals `"deny"`, and otherwise goes on to act. The
parsed answer is whatever came back, so `"denied"`, `"DENY"`, `"block"`, `"error"`, an
empty string and None all execute. The invariant is the one the corpus below names:
unknown verdicts map to deny at the parsing boundary.

This is a regression pattern from the Nobulex failopen corpus
(github.com/arian-gogani/failopen, MIT, Copyright (c) 2026 Arian Gogani), case
`historical/autogen-verdict`. microsoft/autogen PR #7960 executed its action on six
unknown verdicts at commit 0cd67042, and commit ec6cf48c in the same PR (still open,
not in AutoGen main) hardened it to block all six before the issue was filed. It is
not an unresolved AutoGen vulnerability: 0cd67042 is the firing shape and ec6cf48c, an
allowed-set check and a non-permit branch before execution, must not fire. The
corpus's 15-of-36 prevalence figure was withdrawn by its author and is not used here.

**A policy import that may fail.** A guard imports its policy module, catches the
ImportError, and carries on. autonomous-dev's PreToolUse hook did that for a module
that did not exist, so every `mcp__*` call was allowed and the allow-path tests kept
passing. The test that matters is "policy module missing, deny".

What each rule reads, and where it stops, is in the registry's limitations. Both read
Python only, through `parse_python`, one function or module at a time, with no flow
between files.
"""

from __future__ import annotations

import ast
import os
import re
from collections import deque
from pathlib import Path
from typing import Iterator, NamedTuple

from agent_audit_kit.models import Finding

from ._helpers import (
    SKIP_DIRS,
    SOURCE_MAX_BYTES,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    walk_tree,
)

RULE_VERDICT = "AAK-POLICY-VERDICT-FAILOPEN-001"
RULE_IMPORT = "AAK-POLICY-IMPORT-FAILOPEN-001"

# What a verdict is called. The first three say so whatever the code around them does.
# The rest are common words (an HTTP `status`, a UI `action`), so they count only in a
# function or file whose name is about a gate.
_VERDICT_NAMES = frozenset({"verdict", "decision", "approval"})
_WEAK_NAMES = frozenset({"allowed", "action", "status"})
_GATE_WORDS = re.compile(r"polic|guard|gate|govern|approv|authoriz|authz|permission|verdict|hook|pre_?tool|enforc", re.I)

_DENY_WORDS = frozenset({
    "deny", "denied", "reject", "rejected", "block", "blocked", "refuse", "refused",
    "forbid", "forbidden", "disallow", "disallowed",
})
_PERMIT_WORDS = frozenset({
    "allow", "allowed", "approve", "approved", "permit", "permitted", "pass", "ok", "yes", "grant", "granted",
    "accept", "accepted", "execute", "executed", "proceed", "auto_approve",
})
# Calls that keep a value the same word for word: `verdict.lower()`, `str(verdict)`.
_NORMALISERS = frozenset({"lower", "upper", "casefold", "strip", "lstrip", "rstrip", "str"})
# Calls that report or convert rather than act.
_QUIET_CALLS = frozenset({
    "print", "len", "str", "int", "bool", "repr", "isinstance", "getattr", "hasattr", "format", "dict", "list",
    "set", "tuple", "warn", "get", "lower", "upper", "strip", "casefold", "startswith", "endswith", "join",
    "dumps", "loads", "environ", "getenv", "items", "keys", "values", "sorted", "min", "max", "any", "all", "range",
    "enumerate", "time", "monotonic",
})
_LOGGER_NAMES = frozenset({"log", "logger", "logging", "_log", "_logger", "warnings"})

# Modules a failed import of which leaves a gate with nothing to ask, read word by word
# of a dotted or snake_case name, so `aggregate` and `author` are not `gate` and `auth`.
_POLICY_WORD = re.compile(
    r"(?:^|[._])(?:polic(?:y|ies)|auth|authn|authz|authoriz\w*|authentic\w*|valid\w*|guard\w*|permission\w*|acl|rbac"
    r"|enforc\w*|secur\w*|sandbox\w*|allowlist\w*|firewall\w*|gate|gates|gatekeeper)(?:$|[._])", re.I)
# A name that says checks are on, which a handler turns off.
_ENFORCE_FLAG = re.compile(r"enforc|strict|require|security_enabled|policy_enabled|validation_enabled|auth_enabled", re.I)
_IMPORT_ERRORS = frozenset({"ImportError", "ModuleNotFoundError"})
_EXITS = frozenset({"exit", "_exit", "abort", "quit"})

_ALLOW_KEYS = frozenset({"decision", "verdict", "permissiondecision", "action", "effect", "status", "result"})


def _dotted_tail(func: ast.expr) -> str:
    """The last name of a callee: `sys.exit` gives `exit`, `execute` gives `execute`."""
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _is_quiet_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in _LOGGER_NAMES:
        return True
    return _dotted_tail(func) in _QUIET_CALLS


def _own_nodes(nodes: list[ast.stmt], acting_only: bool = False) -> Iterator[ast.AST]:
    """Every node under these statements, in order, without entering a nested function
    or class, whose body runs later or not at all. Each node of a file is therefore
    seen once per function it belongs to, however deep the nesting. With `acting_only`
    a raise and a quiet call are yielded and not entered: building an exception or the
    arguments of a log line is not acting."""
    stack: list[ast.AST] = list(reversed(nodes))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if acting_only and (isinstance(node, ast.Raise) or (isinstance(node, ast.Call) and _is_quiet_call(node))):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _blocks(nodes: list[ast.stmt]) -> Iterator[list[ast.stmt]]:
    """Each statement list under these statements, the outermost first."""
    pending = deque([nodes])
    while pending:
        block = pending.popleft()
        yield block
        for stmt in block:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], ast.stmt):
                    pending.append(inner)
            for handler in getattr(stmt, "handlers", ()):
                pending.append(handler.body)


def _literal_text(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip().lower()
    return None


def _allow_value(node: ast.AST | None) -> bool:
    """Is this a value that says go ahead: True, `"allow"`, `{"decision": "allow"}`?"""
    if isinstance(node, ast.Constant):
        return node.value is True or _literal_text(node) in _PERMIT_WORDS
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if _literal_text(key) in _ALLOW_KEYS and _allow_value(value):
                return True
    return False


def _deny_value(node: ast.AST | None) -> bool:
    """Is this a value that says stop: False, `"deny"`, `{"decision": "deny"}`?"""
    if isinstance(node, ast.Constant):
        return node.value is False or _literal_text(node) in _DENY_WORDS
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if _literal_text(key) in _ALLOW_KEYS and _deny_value(value):
                return True
    return False


def _exit_code(call: ast.Call) -> int | None:
    """The code of a `sys.exit(n)`, 0 for a bare one, None for anything else."""
    if _dotted_tail(call.func) not in _EXITS:
        return None
    if not call.args:
        return 0
    first = call.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, int) else 1


def _stops(block: list[ast.stmt]) -> bool:
    """Does this block refuse, ending without reaching what follows it? `break` is left
    out: it ends a search far more often than it refuses an action."""
    if not block:
        return False
    last = block[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue)):
        return True
    return (isinstance(last, ast.Expr) and isinstance(last.value, ast.Call)
            and _exit_code(last.value) is not None)


# ---- the verdict rule ---------------------------------------------------------------


def _verdict_key(node: ast.AST | None, aliases: dict[str, str]) -> str | None:
    """The verdict name an expression reads: `verdict`, `resp.decision`,
    `body["verdict"]`, `body.get("verdict")`, `str(verdict).lower()`, or a local
    assigned from one of those."""
    while isinstance(node, ast.Call):
        func = node.func
        tail = _dotted_tail(func)
        if tail == "get" and isinstance(func, ast.Attribute) and node.args:
            return _name_key(_literal_text(node.args[0]))
        if tail not in _NORMALISERS:
            return None
        if isinstance(func, ast.Attribute):
            node = func.value
        else:
            node = node.args[0] if node.args else None
    if isinstance(node, ast.Name):
        return aliases.get(node.id) or _name_key(node.id.lower())
    if isinstance(node, ast.Attribute):
        return _name_key(node.attr.lower())
    if isinstance(node, ast.Subscript):
        return _name_key(_literal_text(node.slice))
    return None


def _name_key(name: str | None) -> str | None:
    return name if name in _VERDICT_NAMES or name in _WEAK_NAMES else None


_DENY_EQ, _DENY_NE, _STRICT = "deny-eq", "deny-ne", "strict"


def _literals(node: ast.AST) -> list[str | None]:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [_literal_text(item) for item in node.elts]
    return [_literal_text(node)]


def _compare(test: ast.Compare, aliases: dict[str, str]) -> tuple[str, str] | None:
    """(kind, key) for `verdict == "deny"`, `"deny" == verdict`, `verdict in (...)`."""
    if len(test.ops) != 1:
        return None
    left, op, right = test.left, test.ops[0], test.comparators[0]
    key = _verdict_key(left, aliases)
    if key is None and isinstance(op, (ast.Eq, ast.NotEq)):
        key, right = _verdict_key(right, aliases), left
    if key is None or not isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
        return None
    words = _literals(right)
    denies = any(word in _DENY_WORDS for word in words)
    if isinstance(op, (ast.Eq, ast.In)):
        if denies:
            return _DENY_EQ, key
        # A set by name, or a permit word: only what is on the list goes ahead.
        return (_STRICT, key) if None in words or any(word in _PERMIT_WORDS for word in words) else None
    return (_DENY_NE, key) if denies else (_STRICT, key)


def _classify(test: ast.expr, aliases: dict[str, str]) -> tuple[str, str] | None:
    if isinstance(test, ast.Compare):
        return _compare(test, aliases)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        # `not verdict or verdict == "deny"` is still an exact match on one word.
        for value in test.values:
            if isinstance(value, ast.Compare):
                found = _compare(value, aliases)
                if found is not None and found[0] != _DENY_EQ:
                    return None
        for value in test.values:
            if isinstance(value, ast.Compare):
                found = _compare(value, aliases)
                if found is not None:
                    return found
    return None


def _aliases(own: list[ast.AST]) -> dict[str, str]:
    """Locals assigned from a verdict: `v = resp["verdict"]`, `v = v.lower()`."""
    aliases: dict[str, str] = {}
    for node in own:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            key = _verdict_key(node.value, aliases)
            if key is not None:
                aliases[node.targets[0].id] = key
    return aliases


def _normalised_keys(own: list[ast.AST], aliases: dict[str, str]) -> set[str]:
    """Verdicts whose unknown values were mapped to deny before any check: a deny word
    assigned to the name, or `TABLE.get(raw, "deny")`. A check against an allowed set
    or a permit word anywhere in the function counts as well: only what is on the list
    goes ahead."""
    keys: set[str] = set()
    for node in own:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            key = aliases.get(name) or _name_key(name.lower())
            value = node.value
            if key is None:
                continue
            if _deny_value(value):
                keys.add(key)
            elif (isinstance(value, ast.Call) and _dotted_tail(value.func) == "get"
                  and len(value.args) > 1 and _deny_value(value.args[1])):
                keys.add(key)
        elif isinstance(node, ast.Compare):
            found = _compare(node, aliases)
            if found is not None and found[0] == _STRICT:
                keys.add(found[1])
    return keys


def _reaches_action(rest: list[ast.stmt]) -> bool:
    """Does the code after a check go on to act: a call that does something, or a
    return of a call or a go-ahead? A returned name may be the verdict handed back
    (`return decision`), and a returned word may be another state (`"pending"`), so
    neither counts. A raise's own call builds the exception."""
    for node in _own_nodes(rest, acting_only=True):
        if isinstance(node, ast.Return) and _allow_value(node.value):
            return True
        if isinstance(node, ast.Call) and not _is_quiet_call(node) and _exit_code(node) is None:
            return True
    return False


def _function_gate(name: str, file_stem: str) -> bool:
    return bool(_GATE_WORDS.search(name) or _GATE_WORDS.search(file_stem))


def _verdict_findings(
    func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str, file_stem: str
) -> list[Finding]:
    """One finding per function and verdict name, at the first check of it. A function
    reads a check once per name, so a thousand checks in a row cost one scan of the rest."""
    if func.name.startswith("test_"):
        return []
    own = list(_own_nodes(func.body))
    aliases = _aliases(own)
    normalised = _normalised_keys(own, aliases)
    gate = _function_gate(func.name, file_stem)
    findings: list[Finding] = []
    judged: set[str] = set()
    for block in _blocks(func.body):
        for index, stmt in enumerate(block):
            if not isinstance(stmt, ast.If):
                continue
            found = _classify(stmt.test, aliases)
            if found is None or found[0] == _STRICT or found[1] in judged:
                continue
            kind, key = found
            judged.add(key)
            if key in normalised or (key in _WEAK_NAMES and not gate):
                continue
            after = block[index + 1:]
            if kind == _DENY_EQ:
                opens = (_stops(stmt.body) and _reaches_action(stmt.orelse + after)) or _reaches_action(stmt.orelse)
            else:  # `if verdict != "deny": act()`
                opens = _reaches_action(stmt.body)
            if opens:
                findings.append(make_finding(
                    RULE_VERDICT, rel,
                    f"`{func.name}` refuses only when `{key}` matches a deny word exactly, and goes on to act on "
                    f"anything else: `denied`, `DENY`, `error`, an empty value and None all pass. Map unknown "
                    f"verdicts to deny at the parsing boundary.",
                    stmt.lineno,
                ))
    return findings


# ---- the import rule ----------------------------------------------------------------


def _policy_module(body: list[ast.stmt]) -> str | None:
    """The policy module a try body imports, or None. `from mcp_security_validator
    import validate` names it in the module, and a module named for something else can
    still import a policy word (`from checks import authorize`). A `valid*` name alone
    does not count: over 99,786 site-packages files, the only hits were
    `from logging.config import valid_ident` and `from pydantic import validator`."""
    for stmt in body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if _POLICY_WORD.search(alias.name):
                    return alias.name
        elif isinstance(stmt, ast.ImportFrom):
            module = stmt.module or ""
            if _POLICY_WORD.search(module):
                return module
            for alias in stmt.names:
                word = _POLICY_WORD.search(alias.name)
                if word and not word.group(0).strip("._").lower().startswith("valid"):
                    return module or alias.name
    return None


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    kind = handler.type
    if kind is None:  # a bare `except:` names no exception
        return False
    kinds = kind.elts if isinstance(kind, ast.Tuple) else [kind]
    return any(_dotted_tail(k) in _IMPORT_ERRORS for k in kinds)


def _is_quiet_stmt(stmt: ast.stmt) -> bool:
    """`pass`, a docstring or a log line: a statement that decides nothing."""
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr):
        return isinstance(stmt.value, ast.Constant) or (isinstance(stmt.value, ast.Call) and _is_quiet_call(stmt.value))
    return False


def _blocks_path(block: list[ast.stmt]) -> bool:
    """Does this path refuse: raise, a non-zero exit, or a refusal returned?"""
    for node in _own_nodes(block):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call) and (_exit_code(node) or 0) != 0:
            return True
        if isinstance(node, ast.Return) and _deny_value(node.value):
            return True
    return False


def _allows_path(block: list[ast.stmt]) -> bool:
    """Does this path say go ahead: an allow value returned or printed, or a zero exit?"""
    for node in _own_nodes(block):
        if isinstance(node, ast.Return) and _allow_value(node.value):
            return True
        if isinstance(node, ast.Call):
            if _exit_code(node) == 0:
                return True
            if _dotted_tail(node.func) in ("print", "dumps") and any(_allow_value(a) for a in node.args):
                return True
    return False


def _handler_opens(handler: ast.ExceptHandler) -> tuple[str, set[str]]:
    """What a handler does when the policy module is missing: a reason it opens the gate
    (empty if it does not), and the names it leaves unset for later code to test."""
    if _blocks_path(handler.body):
        return "", set()
    if _allows_path(handler.body):
        return "the handler allows", set()
    missing: set[str] = set()
    for stmt in handler.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            returns = [n for n in _own_nodes(stmt.body) if isinstance(n, ast.Return)]
            if returns and all(_allow_value(n.value) for n in returns):
                return f"the handler binds a stub `{stmt.name}` that allows", set()
        if not isinstance(stmt, ast.Assign) or not isinstance(stmt.targets[0], ast.Name):
            continue
        name, value = stmt.targets[0].id, stmt.value
        if isinstance(value, ast.Lambda) and _allow_value(value.body):
            return f"the handler binds a stub `{name}` that allows", set()
        if isinstance(value, ast.Constant) and value.value in (None, False):
            if _ENFORCE_FLAG.search(name) and value.value is False:
                return f"the handler turns `{name}` off", set()
            missing.add(name)
    return "", missing


def _missing_branch(test: ast.expr, name: str) -> str | None:
    """Which branch of a test runs when `name` is None or False: "body", "orelse", or
    None when the test does not read it. `a and validate is None` still reaches its
    body with the name missing."""
    if isinstance(test, ast.BoolOp):
        for value in test.values:
            branch = _missing_branch(value, name)
            if branch is not None:
                return branch
        return None
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _missing_branch(test.operand, name)
        return {"orelse": "body", "body": "orelse"}.get(inner or "")
    if isinstance(test, ast.Name) and test.id == name:
        return "orelse"
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name) \
            and test.left.id == name and isinstance(test.comparators[0], ast.Constant) \
            and test.comparators[0].value in (None, False):
        if isinstance(test.ops[0], (ast.Is, ast.Eq)):
            return "body"
        if isinstance(test.ops[0], (ast.IsNot, ast.NotEq)):
            return "orelse"
    return None


class _Guarded(NamedTuple):
    """A try around a policy import, with what follows it when in a function."""

    stmt: ast.Try
    module: str
    after: list[ast.stmt] | None


def _statements(tree: ast.Module) -> Iterator[tuple[list[ast.stmt], int, ast.stmt, bool]]:
    """(block, index, statement, in a function) for every statement of a module, each once."""
    pending: list[tuple[list[ast.stmt], bool]] = [(tree.body, False)]
    while pending:
        block, in_function = pending.pop()
        for index, stmt in enumerate(block):
            yield block, index, stmt, in_function
            inside = in_function or isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], ast.stmt):
                    pending.append((inner, inside))
            for handler in getattr(stmt, "handlers", ()):
                pending.append((handler.body, inside))


def _test_opens(stmt: ast.If, branch: str, after: list[ast.stmt], in_function: bool) -> bool:
    """With the name unset, does this test go ahead? `if validate is None: return
    allow`, or a body that decides nothing and falls through; or, for `if validate:
    validate(call)` with no else, what follows it acting, inside a function, where a
    following action is the guarded one. At module level the same shape is an optional
    feature (`if helper: register(helper)`)."""
    if branch == "body":
        body = stmt.body
        return _allows_path(body) or all(_is_quiet_stmt(s) for s in body)
    if stmt.orelse:
        return _allows_path(stmt.orelse) or all(_is_quiet_stmt(s) for s in stmt.orelse)
    if not in_function or _blocks_path(after[:1]):
        return False
    return _allows_path(after) or _reaches_action(after)


def _later_tests(statements: list[tuple[list[ast.stmt], int, ast.stmt, bool]], names: set[str]) -> dict[str, int]:
    """name -> the line of the first test of it that goes ahead with it unset. One pass
    over the module whatever the number of imports, each test read for the names it holds."""
    opened: dict[str, int] = {}
    if not names:
        return opened
    for block, index, stmt, in_function in statements:
        if not isinstance(stmt, ast.If):
            continue
        mentioned = {n.id for n in ast.walk(stmt.test) if isinstance(n, ast.Name)} & names
        for name in sorted(mentioned - set(opened)):
            branch = _missing_branch(stmt.test, name)
            if branch is not None and _test_opens(stmt, branch, block[index + 1:], in_function):
                opened[name] = stmt.lineno
    return opened


def _import_findings(tree: ast.Module, rel: str) -> list[Finding]:
    statements = list(_statements(tree))
    guarded: list[_Guarded] = []
    for block, index, stmt, in_function in statements:
        if isinstance(stmt, ast.Try):
            module = _policy_module(stmt.body)
            if module is not None:
                guarded.append(_Guarded(stmt, module, block[index + 1:] if in_function else None))
    handled = [(g, h, *_handler_opens(h)) for g in guarded for h in g.stmt.handlers if _catches_import_error(h)]
    opened = _later_tests(statements, {name for *_, reason, missing in handled if not reason for name in missing})
    found: list[tuple[int, str]] = []
    for item, handler, reason, missing in handled:
        for name in sorted(missing):
            if not reason and name in opened:
                reason = f"`{name}` is left unset and the test of it on line {opened[name]} goes ahead"
        checks = any(isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) for s in item.stmt.body)
        if (not reason and item.after is not None and checks and all(_is_quiet_stmt(s) for s in handler.body)
                and _reaches_action(item.after)):
            reason = "the check in the try is skipped and the code goes on to act"
        if reason:
            found.append((handler.lineno, f"The import of policy module `{item.module}` may fail, and then {reason}, "
                          "so a missing policy allows everything. Deny on the ImportError: raise, or exit with the "
                          "code your gate reads as a refusal, and test \"policy module missing, deny\"."))
    return [make_finding(RULE_IMPORT, rel, evidence, line) for line, evidence in sorted(found)]


# ---- the walk -----------------------------------------------------------------------


def _analyse(tree: ast.Module, rel: str, file_stem: str) -> list[Finding]:
    findings = _import_findings(tree, rel)
    stack: list[ast.AST] = [tree]
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node)
        stack.extend(ast.iter_child_nodes(node))
    for func in sorted(functions, key=lambda f: f.lineno):
        findings.extend(_verdict_findings(func, rel, file_stem))
    return findings


# Cheap tests that keep most files from being parsed at all.
_HINT_RE = re.compile(r"ImportError|ModuleNotFoundError|verdict|decision|approval|\bstatus\b|\baction\b|\ballowed\b")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report fail-open verdict checks and policy imports in Python source.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            try:
                text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
            except OSError:
                continue
            if not _HINT_RE.search(text):
                continue
            try:
                tree = parse_python(text, path)
            except (SyntaxError, ValueError):
                continue
            rel = path.relative_to(project_root).as_posix()
            with refusing_overflow(path):
                found = walk_tree(_analyse, tree, rel, path.stem)
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["RULE_VERDICT", "RULE_IMPORT", "scan"]
