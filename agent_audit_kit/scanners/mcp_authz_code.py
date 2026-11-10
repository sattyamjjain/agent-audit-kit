"""Three shapes of authorization in MCP server code that pass while deciding nothing.

* AAK-AUTHZ-CALLER-INPUT-001: the decision reads a tenant, org, user, role or scope from the
  tool's own arguments. The check runs and passes, evaluating what the caller sent. It has to
  read the authenticated principal; a parameter may only be compared with it.
* AAK-MCP-AUTHZ-COVERAGE-001: a server checks scopes in its tools/call handler and not in
  resources/read, prompts/get or completion/complete, which tend to get the check later; a
  separate check on one HTTP transport and not the other; or a handler that runs when the
  principal contextvar is unset, where `.get(None)` reads as allow.
* AAK-MCP-TOKENVERIFIER-AUD-001: a python-sdk resource server with `resource_server_url=None`,
  which serves no protected-resource metadata and leaves the audience check to the verifier, or
  a custom `verify_token` that never reads an audience or a resource. The spec says servers MUST
  validate that a token was issued for them. AAK-MCP-SDK-CVE-2026-59951-001 pins the SDK's own
  audience-blind check by version; this reads the code shape on any version.

Python only, through `parse_python`, one file at a time. What each rule reads, and where it
stops, is in the registry's limitations.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Iterable, Iterator

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, SOURCE_MAX_BYTES, make_finding, parse_python, read_text_capped, refusing_overflow, walk_tree

RULE_CALLER = "AAK-AUTHZ-CALLER-INPUT-001"
RULE_COVERAGE = "AAK-MCP-AUTHZ-COVERAGE-001"
RULE_AUD = "AAK-MCP-TOKENVERIFIER-AUD-001"

_ID_NAMES = frozenset({"org_id", "organization_id", "tenant", "tenant_id", "user_id", "account_id"})
_PRIVILEGE_NAMES = frozenset({"role", "roles", "scope", "scopes"})
_ARG_MAPS = frozenset({"arguments", "args", "params", "kwargs", "input", "tool_input"})
_PRIVILEGE_WORDS = frozenset({"admin", "administrator", "owner", "root", "superuser", "sudo", "write", "delete"})
_AUTHZ_CALL = re.compile(
    r"^_?(?:authori[sz]e\w*|is_authori[sz]ed|check_(?:access|permission|permissions|scope|scopes|role|authz|authorization)"
    r"|has_(?:permission|permissions|access|role|scope|scopes)|can_(?:access|read|write|edit|delete|manage)|enforce\w*"
    r"|require_(?:role|scope|scopes|permission|auth\w*)|verify_(?:access|scope|scopes|permission|permissions)"
    r"|is_allowed|assert_(?:access|permission|scope)|ensure_(?:access|permission|scope)|validate_(?:access|scope|scopes|permission))$",
    re.I,
)
_PRINCIPAL_WORD = re.compile(
    r"principal|current_user|\bctx\b|context|access_token|\btoken\b|claims|identity|\bsession\b|\bauth\b|subject|\bgrant\b",
    re.I,
)
_DENIAL_ERROR = re.compile(r"permission|forbidden|unauthori|accessdenied|access_denied|autherror|authorization", re.I)

_HANDLER_KINDS = {
    "tool": "tools/call", "call_tool": "tools/call",
    "resource": "resources/read", "read_resource": "resources/read",
    "prompt": "prompts/get", "get_prompt": "prompts/get",
    "completion": "completion/complete", "complete": "completion/complete",
}
_SCOPE_READS = frozenset({"scopes", "permissions", "roles", "required_scopes"})
_HTTP_TRANSPORTS = frozenset({"sse", "streamable-http", "streamable_http", "streamable"})
# Read word by word of the name: `_socket_factory` holds `actor`, and is no principal.
_CONTEXT_NAME = re.compile(r"(?:^|_)(?:principal|identity|auth\w*|user|subject|token|actor)(?:_|$)", re.I)
_AUDIENCE_RE = re.compile(r"\baud\b|audience|validate_token_resource|check_resource_allowed|resource_url|expected_resource", re.I)


def _tail(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _own_nodes(nodes: list[ast.stmt]) -> Iterator[ast.AST]:
    stack: list[ast.AST] = list(reversed(nodes))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _blocks(nodes: list[ast.stmt]) -> Iterator[list[ast.stmt]]:
    pending = [nodes]
    while pending:
        block = pending.pop()
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


def _handler_kind(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr in _HANDLER_KINDS:
            return _HANDLER_KINDS[target.attr]
    return None


def _mentions_principal(nodes: Iterable[ast.AST]) -> bool:
    for root in nodes:
        for node in ast.walk(root):
            word = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
            if word and _PRINCIPAL_WORD.search(word):
                return True
    return False


# ---- a decision on what the caller sent ---------------------------------------------


def _caller_names(func: ast.FunctionDef | ast.AsyncFunctionDef, own: list[ast.AST]) -> dict[str, str]:
    """Local name -> the argument it holds: a parameter named `org_id`, or a local assigned
    from `arguments["org_id"]`."""
    args = func.args
    held = {a.arg: a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if a.arg in _ID_NAMES or a.arg in _PRIVILEGE_NAMES}
    for node in own:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            key = _argument_key(node.value)
            if key:
                held[node.targets[0].id] = key
    return held


def _argument_key(node: ast.AST) -> str | None:
    """`arguments["org_id"]` and `arguments.get("org_id")` name the argument they read."""
    target: ast.AST | None = None
    key: ast.AST | None = None
    if isinstance(node, ast.Subscript):
        target, key = node.value, node.slice
    elif isinstance(node, ast.Call) and _tail(node.func) == "get" and isinstance(node.func, ast.Attribute) and node.args:
        target, key = node.func.value, node.args[0]
    if isinstance(target, ast.Name) and target.id in _ARG_MAPS and isinstance(key, ast.Constant) \
            and (key.value in _ID_NAMES or key.value in _PRIVILEGE_NAMES):
        return str(key.value)
    return None


def _held_argument(node: ast.AST, held: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return held.get(node.id)
    return _argument_key(node)


def _privilege_compare(test: ast.Compare, held: dict[str, str]) -> tuple[str, str] | None:
    """(argument, what it is compared with) for `role == "admin"` or `"admin" in roles`."""
    if len(test.ops) != 1 or not isinstance(test.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
        return None
    left, right = test.left, test.comparators[0]
    for mine, other in ((left, right), (right, left)):
        key = _held_argument(mine, held)
        if key in _PRIVILEGE_NAMES:
            items = other.elts if isinstance(other, (ast.Tuple, ast.List, ast.Set)) else [other]
            for item in items:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    word = item.value.lower()
                    if word in _PRIVILEGE_WORDS or ":" in word:
                        return key or "", item.value
    return None


def _denies(block: list[ast.stmt]) -> bool:
    for node in _own_nodes(block):
        if isinstance(node, ast.Raise) and node.exc is not None:
            name = _tail(node.exc.func) if isinstance(node.exc, ast.Call) else _tail(node.exc)
            if _DENIAL_ERROR.search(name):
                return True
    return False


def _caller_findings(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    if _handler_kind(func) is None or func.name.startswith("test_"):
        return []
    own = list(_own_nodes(func.body))
    held = _caller_names(func, own)
    if not held and not any(_argument_key(n) for n in own):
        return []
    for node in own:
        if isinstance(node, ast.Call) and _AUTHZ_CALL.match(_tail(node.func)):
            values = [*node.args, *(k.value for k in node.keywords)]
            keys = [k for k in (_held_argument(v, held) for v in values) if k]
            if keys and not _mentions_principal(values):
                return [_caller_finding(rel, func.name, keys[0], f"`{_tail(node.func)}`", node.lineno)]
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            compared = _privilege_compare(node.test, held)
            if compared and not _mentions_principal([node.test]):
                return [_caller_finding(rel, func.name, compared[0], f'a comparison with "{compared[1]}"', node.lineno)]
            ids = _id_compare(node.test, held)
            if ids and _denies(node.body) and not _mentions_principal([node.test]):
                return [_caller_finding(rel, func.name, ids, "a check that refuses", node.lineno)]
    return []


def _id_compare(test: ast.Compare, held: dict[str, str]) -> str | None:
    if len(test.ops) != 1 or not isinstance(test.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
        return None
    for mine in (test.left, test.comparators[0]):
        key = _held_argument(mine, held)
        if key in _ID_NAMES:
            return key
    return None


def _caller_finding(rel: str, name: str, key: str, how: str, line: int) -> Finding:
    return make_finding(
        RULE_CALLER, rel,
        f"Tool handler `{name}` decides access with {how} on `{key}`, a value the caller sends in the tool's "
        "arguments, so the check passes while evaluating attacker input. Read it from the authenticated principal "
        "(the request context, the access token), and compare any parameter with that.",
        line,
    )


# ---- coverage -------------------------------------------------------------------------


def _checks_authorization(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _AUTHZ_CALL.match(_tail(target)):
            return True
    for node in _own_nodes(func.body):
        if isinstance(node, ast.Call) and _AUTHZ_CALL.match(_tail(node.func)):
            return True
        if isinstance(node, ast.Compare):
            for side in (node.left, *node.comparators):
                if _tail(side) in _SCOPE_READS:
                    return True
    return False


def _handler_gaps(functions: list[ast.FunctionDef | ast.AsyncFunctionDef], rel: str) -> list[Finding]:
    handlers = [(func, kind) for func in functions for kind in [_handler_kind(func)] if kind]
    if not any(kind == "tools/call" and _checks_authorization(func) for func, kind in handlers):
        return []
    return [
        make_finding(
            RULE_COVERAGE, rel,
            f"The tools/call handler checks authorization, and the {kind} handler `{func.name}` does not, so the same "
            "server hands out through one door what it refuses at another. Call one shared check from every handler.",
            func.lineno,
        )
        for func, kind in handlers
        if kind != "tools/call" and not _checks_authorization(func)
    ]


def _literal_transport(test: ast.expr) -> str | None:
    """The HTTP transport in `transport == "sse"`."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        name, value = test.left, test.comparators[0]
        if "transport" in _tail(name).lower() and isinstance(value, ast.Constant) and value.value in _HTTP_TRANSPORTS:
            return str(value.value)
    return None


def _transport_findings(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    """A check on one HTTP transport only. `transport != "stdio"` is not read: stdio has
    no network login to check, and the spec says it should not use this flow."""
    for node in _own_nodes(func.body):
        if isinstance(node, ast.If):
            transport = _literal_transport(node.test)
            if transport and not node.orelse and any(
                    isinstance(n, ast.Call) and _AUTHZ_CALL.match(_tail(n.func)) for n in _own_nodes(node.body)):
                return [make_finding(
                    RULE_COVERAGE, rel,
                    f"`{func.name}` checks authorization only when the transport is `{transport}`, so the other HTTP "
                    "transport takes a different path. Two code paths for one policy is where they drift apart: make "
                    "one decision that both share.",
                    node.lineno,
                )]
    return []


def _missing_branch(test: ast.expr, name: str) -> str | None:
    """Which branch runs with `name` unset: "body", "orelse", or None if it is not read."""
    if isinstance(test, ast.BoolOp):
        if isinstance(test.op, ast.And):
            for value in test.values:
                branch = _missing_branch(value, name)
                if branch == "orelse":
                    return "orelse"  # `p and ...`: the body cannot run with it unset
        for value in test.values:
            branch = _missing_branch(value, name)
            if branch is not None:
                return branch
        return None
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return {"orelse": "body", "body": "orelse"}.get(_missing_branch(test.operand, name) or "")
    if isinstance(test, ast.Name) and test.id == name:
        return "orelse"
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name) \
            and test.left.id == name and isinstance(test.comparators[0], ast.Constant) \
            and test.comparators[0].value is None:
        if isinstance(test.ops[0], ast.Is):
            return "body"
        if isinstance(test.ops[0], ast.IsNot):
            return "orelse"
    return None


def _refuses(block: list[ast.stmt]) -> bool:
    """Does this path stop the request: a raise, or a refusal returned?"""
    for node in _own_nodes(block):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) \
                and node.value.value in (False, None, "deny", "denied"):
            return True
    return False


def _context_findings(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    """A contextvar read with a None default, and a test of it that goes ahead when unset."""
    names: dict[str, str] = {}
    for node in _own_nodes(func.body):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Call) and _tail(node.value.func) == "get" \
                and isinstance(node.value.func, ast.Attribute) and len(node.value.args) == 1 \
                and isinstance(node.value.args[0], ast.Constant) and node.value.args[0].value is None:
            source = _tail(node.value.func.value)
            if _CONTEXT_NAME.search(source) and source.lower() not in ("request", "headers", "environ"):
                names[node.targets[0].id] = source
    if not names:
        return []
    for block in _blocks(func.body):
        for index, stmt in enumerate(block):
            if not isinstance(stmt, ast.If):
                continue
            for name, source in names.items():
                branch = _missing_branch(stmt.test, name)
                if branch is None:
                    continue
                path = stmt.body if branch == "body" else (stmt.orelse or block[index + 1:index + 2])
                if not _refuses(path):
                    return [make_finding(
                        RULE_COVERAGE, rel,
                        f"`{func.name}` reads `{source}.get(None)` and goes ahead when it is unset, so a request that "
                        "reaches this code with no principal is treated as allowed. Refuse when there is no principal.",
                        stmt.lineno,
                    )]
    return []


# ---- the audience ---------------------------------------------------------------------


def _is_stub(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A Protocol's method or an abstract one: a docstring, `...`, `pass` or NotImplementedError."""
    for stmt in func.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Pass) or isinstance(stmt, ast.Raise):
            continue
        return False
    return True


def _aud_findings(tree: ast.Module, rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    has_verifier = "token_verifier" in text
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _tail(node.func) == "AuthSettings" and has_verifier:
            for keyword in node.keywords:
                if keyword.arg == "resource_server_url" and isinstance(keyword.value, ast.Constant) \
                        and keyword.value.value is None:
                    findings.append(make_finding(
                        RULE_AUD, rel,
                        "`AuthSettings(resource_server_url=None)` with a `token_verifier` serves no protected-resource "
                        "metadata, sends no `resource_metadata` in its 401, and leaves the audience check to the "
                        "verifier. Set the server's canonical URL, and check the token's audience.",
                        node.lineno,
                    ))
        if isinstance(node, ast.ClassDef) and not _AUDIENCE_RE.search(text):
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == "verify_token" \
                        and not _is_stub(stmt):
                    findings.append(make_finding(
                        RULE_AUD, rel,
                        f"`{node.name}.verify_token` never reads an audience or a resource, so a token issued for "
                        "another server is accepted. The MCP spec says servers MUST validate that a token was issued "
                        "for them as the intended audience.",
                        stmt.lineno,
                    ))
    return sorted(findings, key=lambda f: f.line_number or 0)


# ---- the walk -------------------------------------------------------------------------


def _analyse(tree: ast.Module, rel: str, text: str) -> list[Finding]:
    functions = sorted((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
                       key=lambda f: f.lineno)
    findings = _handler_gaps(functions, rel)
    findings.extend(_aud_findings(tree, rel, text))
    for func in functions:
        findings.extend(_caller_findings(func, rel))
        findings.extend(_transport_findings(func, rel))
        findings.extend(_context_findings(func, rel))
    return findings


_HINT_RE = re.compile(r"\.(?:tool|call_tool)\b|TokenVerifier|verify_token|token_verifier|\.get\(None\)|\btransport\b")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report authorization that reads caller input, misses a handler, or skips the audience.

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
                found = walk_tree(_analyse, tree, rel, text)
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["RULE_CALLER", "RULE_COVERAGE", "RULE_AUD", "scan"]
