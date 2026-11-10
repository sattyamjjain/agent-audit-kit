"""Gates that let the action through when they have nothing to say.

* AAK-POLICY-OPTIONAL-TRUST-001: a security check written `if x is False:` on a parameter that
  may be None, so None passes, or a trust parameter whose default is the passing value. A caller
  that never ran the check then reads the same as one that ran it and passed.
* AAK-HOOK-FAILOPEN-001: a Claude Code PreToolUse hook whose script can exit with a code other
  than 2 on an error. Only exit 2 blocks, and any other failure lets the call go ahead, so a gate
  that crashes opens. The same rule reports settings that lean on `permissions.ask` while bypass
  mode stays available.
  Of 152 public repositories with a PreToolUse hook in `.claude/settings.json` (code search,
  2026-11-07), 250 command handlers named 135 scripts this could read, 106 of those can refuse, and
  59 fire: 26 on `set -e`, 13 on an except that lets the call through, 17 on no handler at all
  (8 Python, 9 Node) and 3 on an explicit exit.
* AAK-AGENT-SUBAGENT-TOOLS-001: a project subagent with `tools: *` or no `tools` line in a project
  whose MCP config connects servers that write. It inherits every one of them.
  AAK-AGENT-COMPOSE-001 reads the capability union of a set of skills; subagents are not skills, so
  the two do not overlap.

One file at a time. What each rule reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from agent_audit_kit.models import Finding

from ._helpers import (
    CONFIG_MAX_BYTES,
    SKIP_DIRS,
    SOURCE_MAX_BYTES,
    find_line_number,
    find_line_numbers,
    hook_command,
    iter_hook_handlers,
    iter_mcp_servers,
    loads_json,
    loads_jsonc,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    walk_tree,
)
from .hook_injection import SETTINGS_FILES, _hook_sources, _shell_words
from .skill_composition import _parse_frontmatter

RULE_OPTIONAL = "AAK-POLICY-OPTIONAL-TRUST-001"
RULE_HOOK = "AAK-HOOK-FAILOPEN-001"
RULE_SUBAGENT = "AAK-AGENT-SUBAGENT-TOOLS-001"

# Read word by word of a snake_case name, so `validate` and `allowed_hosts` are not one of these.
# A name that alone states a check came out clean:
_ASSERT_WORDS = frozenset({"verified", "trusted", "authenticated", "authorized", "authorised", "attested"})
# Common words that say so only beside what was checked (`key_matches_pin`, `signature_valid`):
_WEAK_ASSERT_WORDS = frozenset({"valid", "matches", "matched", "signed", "approved", "permitted", "allowed", "available"})
# The same two grades for a name that states a check failed:
_REFUTE_WORDS = frozenset({"revoked", "tampered", "compromised", "forged", "untrusted", "unverified"})
_WEAK_REFUTE_WORDS = frozenset({"expired", "denied", "blocked"})
_SUBJECT_WORDS = frozenset({
    "key", "pin", "signature", "sig", "cert", "certificate", "token", "hash", "digest", "credential",
    "credentials", "issuer", "audience", "nonce", "caller", "client", "session", "origin",
})
# `require_verified=True` asks for the check, and `allow_expired=False` refuses by default. A
# directive like these is the safe default, not an assertion that a check passed.
_DIRECTIVE_WORDS = frozenset({
    "not", "no", "non", "skip", "without", "require", "requires", "required", "need", "needs", "must",
    "check", "allow", "only", "ignore", "enforce", "strict",
})
_NOT_DEPLOYED = frozenset({
    "test", "tests", "testing", "fixture", "fixtures", "example", "examples", "sample", "samples", "demo", "demos",
})
_TRUST_HINT_RE = re.compile(
    r"verified|trusted|authenticated|authori[sz]ed|attested|revoked|tampered|compromised|forged"
    r"|_valid|valid_|match|signed|approved|permitted|allowed|_available|expired|denied|blocked"
)
_EXIT_NAMES = frozenset({"exit", "quit", "_exit"})


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


def _exit_code(node: ast.AST) -> int | None:
    """The code a `sys.exit(...)` or `raise SystemExit(...)` states, or None if it states none."""
    if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and _tail(node.exc.func) == "SystemExit":
        args = node.exc.args
    elif isinstance(node, ast.Call) and _tail(node.func) in _EXIT_NAMES:
        args = node.args
    else:
        return None
    if not args:
        return 0
    if not isinstance(args[0], ast.Constant):
        return None
    value = args[0].value
    if value is None:
        return 0
    if isinstance(value, str):  # sys.exit("message") prints it and exits 1
        return 1
    return int(value) if isinstance(value, int) else None


# -- AAK-POLICY-OPTIONAL-TRUST-001 ------------------------------------------------------------


def _passing_value(name: str) -> bool | None:
    """The value of a trust parameter that reads as a clean check, or None for any other name."""
    words = set(name.lower().strip("_").split("_"))
    if words & _DIRECTIVE_WORDS:
        return None
    if words & _REFUTE_WORDS or (words & _WEAK_REFUTE_WORDS and words & _SUBJECT_WORDS):
        return False
    if words & _ASSERT_WORDS or (words & _WEAK_ASSERT_WORDS and words & _SUBJECT_WORDS):
        return True
    return None


def _params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[tuple[ast.arg, ast.expr | None]]:
    positional = [*func.args.posonlyargs, *func.args.args]
    defaults = [None] * (len(positional) - len(func.args.defaults)) + list(func.args.defaults)
    yield from zip(positional, defaults)
    yield from zip(func.args.kwonlyargs, func.args.kw_defaults)


_QUOTED_OPTIONAL_BOOL_RE = re.compile(
    r"(?:typing\.)?Optional\s*\[\s*bool\s*\]|bool\s*\|\s*None|None\s*\|\s*bool"
    r"|(?:typing\.)?Union\s*\[\s*(?:bool\s*,\s*None|None\s*,\s*bool)\s*\]"
)


def _optional_bool(node: ast.expr | None) -> bool:
    """Is this annotation an optional bool, in any of its spellings?"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(_QUOTED_OPTIONAL_BOOL_RE.fullmatch(node.value.strip()))
    sides: tuple[ast.expr, ...]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        sides = (node.left, node.right)
    elif isinstance(node, ast.Subscript) and _tail(node.value) == "Optional":
        return isinstance(node.slice, ast.Name) and node.slice.id == "bool"
    elif isinstance(node, ast.Subscript) and _tail(node.value) == "Union" and isinstance(node.slice, ast.Tuple):
        sides = tuple(node.slice.elts)
    else:
        return False
    return (
        any(isinstance(s, ast.Name) and s.id == "bool" for s in sides)
        and any(isinstance(s, ast.Constant) and s.value is None for s in sides)
    )


@dataclass
class _Reads:
    """What one function's own code does with its names, gathered in one pass."""

    refuses_if_false: dict[str, int] = field(default_factory=dict)  # `if x is False:`
    refuses_if_true: dict[str, int] = field(default_factory=dict)  # `if x is True:`
    refuses_if_falsy: dict[str, int] = field(default_factory=dict)  # `if not x:`
    refuses_if_truthy: dict[str, int] = field(default_factory=dict)  # `if x:`
    none_checked: set[str] = field(default_factory=set)
    true_checked: set[str] = field(default_factory=set)
    false_checked: set[str] = field(default_factory=set)
    truth_read: set[str] = field(default_factory=set)
    handed_off: set[str] = field(default_factory=set)


def _stops(block: list[ast.stmt]) -> bool:
    return any(
        isinstance(node, (ast.Raise, ast.Return)) or _exit_code(node) is not None
        for node in _own_nodes(block)
    )


def _read_term(term: ast.expr, line: int, stops: bool, reads: _Reads) -> None:
    """One operand of an `if` test: note the branch when it stops on that value."""
    if isinstance(term, ast.Compare) and isinstance(term.left, ast.Name) and len(term.ops) == 1 \
            and isinstance(term.ops[0], (ast.Is, ast.Eq)) and isinstance(term.comparators[0], ast.Constant):
        value = term.comparators[0].value
        table = reads.refuses_if_false if value is False else reads.refuses_if_true if value is True else None
        if table is not None and stops:
            table.setdefault(term.left.id, line)
    elif isinstance(term, ast.UnaryOp) and isinstance(term.op, ast.Not) and isinstance(term.operand, ast.Name):
        if stops:
            reads.refuses_if_falsy.setdefault(term.operand.id, line)
    elif isinstance(term, ast.Name):
        reads.truth_read.add(term.id)
        if stops:
            reads.refuses_if_truthy.setdefault(term.id, line)


def _read_function(func: ast.FunctionDef | ast.AsyncFunctionDef) -> _Reads:
    reads = _Reads()
    for node in _own_nodes(func.body):
        if isinstance(node, ast.If):
            stops = _stops(node.body)
            stack: list[ast.expr] = [node.test]
            while stack:
                term = stack.pop()
                if isinstance(term, ast.BoolOp):
                    stack.extend(term.values)
                else:
                    _read_term(term, node.lineno, stops, reads)
        elif isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and len(node.ops) == 1 \
                and isinstance(node.comparators[0], ast.Constant):
            value = node.comparators[0].value
            if value is None:
                reads.none_checked.add(node.left.id)
            elif value is True:
                reads.true_checked.add(node.left.id)
            elif value is False:
                reads.false_checked.add(node.left.id)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Name):
            reads.truth_read.add(node.operand.id)
        elif isinstance(node, ast.Call):
            for argument in [*node.args, *(k.value for k in node.keywords)]:
                inner = argument.value if isinstance(argument, ast.Starred) else argument
                if isinstance(inner, ast.Name):
                    reads.handed_off.add(inner.id)
    return reads


def _trust_message(
    func_name: str, arg: ast.arg, default: ast.expr | None, reads: _Reads, passing: bool,
) -> tuple[str, int] | None:
    """Why this parameter passes on no check at all, and where, or None if it does not."""
    name = arg.arg
    exact = reads.refuses_if_false if passing else reads.refuses_if_true
    loose = reads.refuses_if_falsy if passing else reads.refuses_if_truthy
    may_be_none = (isinstance(default, ast.Constant) and default.value is None) or _optional_bool(arg.annotation)
    answered = (
        name in reads.none_checked
        or name in (reads.true_checked if passing else reads.false_checked)
        or name in reads.truth_read
        or name in reads.handed_off
    )
    if may_be_none and name in exact and not answered:
        return (
            f"{func_name}() refuses only on `{name} is {not passing}`, so None passes: "
            f"a caller that never ran the check reads as one that ran it and passed",
            exact[name],
        )
    if isinstance(default, ast.Constant) and default.value is passing:
        line = exact.get(name) or loose.get(name)
        if line:
            return (
                f"{func_name}({name}={passing}) refuses when told the check failed, and the default says "
                f"it passed: a caller that leaves it out skips the check",
                line,
            )
    return None


def _trust_findings(tree: ast.Module, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = [(a, d, p) for a, d in _params(func) if (p := _passing_value(a.arg)) is not None]
        if not params:
            continue
        reads = _read_function(func)
        for arg, default, passing in params:
            message = _trust_message(func.name, arg, default, reads, passing)
            if message:
                out.append(make_finding(RULE_OPTIONAL, rel, message[0], message[1]))
    return out


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (
        any(p in _NOT_DEPLOYED for p in parts[:-1])
        or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"
    )


def _python_findings(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(project_root).as_posix()
            if _is_test_path(rel):
                continue
            try:
                text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
            except OSError:
                continue
            if not _TRUST_HINT_RE.search(text):
                continue
            try:
                tree = parse_python(text, path)
            except (SyntaxError, ValueError):
                continue
            with refusing_overflow(path):
                found = walk_tree(_trust_findings, tree, rel)
                scanned.add(rel)
                findings.extend(found)
    return findings


# -- AAK-HOOK-FAILOPEN-001: the script a hook runs ---------------------------------------------

_SCRIPT_KINDS = {
    ".py": "python", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".js": "node", ".mjs": "node", ".cjs": "node", ".ts": "node",
}
_ROOT_VAR_RE = re.compile(r"\$\{?(CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR)\}?/*")
# A script that can block at all: one with nothing to enforce is a logger, and a logger that
# crashes opens nothing.
_EXITS_TWO_RE = re.compile(r"\bexit\s+2\b|\b_?exit\(\s*2\s*\)|SystemExit\(\s*2\s*\)|exitCode\s*=\s*2|\breturn\s+2\b")
_DECIDES_RE = re.compile(r"permissionDecision|[\"']decision[\"']")
_REFUSAL_WORD_RE = re.compile(r"[\"'](?:deny|block|ask)[\"']")


def _is_gate(text: str) -> bool:
    return bool(_EXITS_TWO_RE.search(text) or (_DECIDES_RE.search(text) and _REFUSAL_WORD_RE.search(text)))


_SWALLOW_RE = re.compile(r"(?:\|\||;)\s*(?:true|:|exit\s+0)\s*$")
_EXIT_TWO_RE = re.compile(r"\bexit\s+2\b")
_HARMLESS_CALLS = frozenset({
    "compile", "Path", "frozenset", "set", "dict", "list", "tuple", "getLogger", "getenv", "get", "join", "dirname",
    "abspath", "basename", "expanduser", "resolve", "print", "write", "flush", "insert", "append",
    "getcwd", "str", "int", "bool", "len", "repr", "sorted", "dumps",
})


def _usage_path(lines: list[str], number: int) -> bool:
    """Does this exit follow a usage message? A script that is also a command line tool has one."""
    return any("usage" in line.lower() for line in lines[max(0, number - 3):number])


def _harmless(value: ast.expr | None) -> bool:
    if value is None:
        return True
    for node in ast.walk(value):
        if isinstance(node, ast.Subscript):
            return False
        if isinstance(node, ast.Call) and _tail(node.func) not in _HARMLESS_CALLS and _exit_code(node) is None:
            return False
    return True


def _blocks_action(nodes: list[ast.stmt], helpers: frozenset[str] = frozenset()) -> bool:
    """Does this path exit 2, return 2, say deny, or call a helper that does?"""
    for node in _own_nodes(nodes):
        if _exit_code(node) == 2:
            return True
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and node.value.value == 2:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.lower() in ("deny", "block"):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in helpers:
            return True
    return False


def _closing_try(stmt: ast.Try, helpers: frozenset[str]) -> bool:
    for handler in stmt.handlers:
        caught = handler.type
        names = {_tail(e) for e in (caught.elts if isinstance(caught, ast.Tuple) else [caught])} if caught else set()
        if (caught is None or names & {"Exception", "BaseException"}) and _blocks_action(handler.body, helpers):
            return True
    return False


def _called_entry(stmt: ast.stmt) -> tuple[str, bool] | None:
    """The function of this module a statement runs, and whether its result is the exit code."""
    call = stmt.value if isinstance(stmt, ast.Expr) else stmt.exc if isinstance(stmt, ast.Raise) else None
    exits = False
    if isinstance(call, ast.Call) and _tail(call.func) in (_EXIT_NAMES | {"SystemExit"}) and call.args:
        call, exits = call.args[0], True
    if isinstance(call, ast.Call) and _tail(call.func) == "run" and call.args:  # asyncio.run(main())
        call = call.args[0]
    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
        return call.func.id, exits
    return None


def _first_open(
    stmts: list[ast.stmt], functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    helpers: frozenset[str], entered: set[str],
) -> ast.stmt | None:
    """The first statement on the way in that can raise with no closing handler around it."""
    for stmt in stmts:
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Pass, ast.Global, ast.Nonlocal)):
            continue
        if isinstance(stmt, ast.Try) and _closing_try(stmt, helpers):
            continue
        entry = _called_entry(stmt)
        if entry and entry[0] in functions:
            if entry[0] not in entered:
                entered.add(entry[0])
                inner = _first_open(functions[entry[0]].body, functions, helpers, entered)
                if inner is not None:
                    return inner
            continue
        if isinstance(stmt, ast.If) and _harmless(stmt.test):
            inner = _first_open([*stmt.body, *stmt.orelse], functions, helpers, entered)
            if inner is not None:
                return inner
            continue
        if isinstance(stmt, (ast.Expr, ast.Return, ast.Assign, ast.AnnAssign)) and _harmless(stmt.value):
            continue
        if _exit_code(stmt) is not None:
            continue
        return stmt
    return None


def _python_open(tree: ast.Module, lines: list[str]) -> tuple[str, int] | None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Call, ast.Raise)):
            continue
        code = _exit_code(node)
        if code is not None and code not in (0, 2) and not _usage_path(lines, node.lineno):
            return f"it exits {code} on a path of its own, and only exit 2 blocks", node.lineno
    functions = {
        f.name: f for f in tree.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    helpers = frozenset(name for name, func in functions.items() if _blocks_action(func.body))
    result = next(_entry_results(tree, functions), None)
    if result is not None:
        return f"its entry point returns {result[0]} as the exit code, and only exit 2 blocks", result[1]
    opened = _first_open(tree.body, functions, helpers, set())
    if isinstance(opened, ast.Try):
        return "this except lets the call through on an error, and only exit 2 blocks", opened.lineno
    if opened is not None:
        return "an uncaught exception here exits 1, and only exit 2 blocks", opened.lineno
    return None


def _entry_results(
    tree: ast.Module, functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> Iterator[tuple[int, int]]:
    """`return 1` in a function whose result `sys.exit(main())` turns into the exit code."""
    done: set[str] = set()
    for stmt in _own_nodes(tree.body):
        if not isinstance(stmt, ast.stmt):
            continue
        entry = _called_entry(stmt)
        if not entry or not entry[1] or entry[0] not in functions or entry[0] in done:
            continue
        done.add(entry[0])
        for node in _own_nodes(functions[entry[0]].body):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, int) and node.value.value not in (0, 2):
                yield int(node.value.value), node.lineno


_SH_EXIT_RE = re.compile(r"(?:^|[\s;&|({'\"])exit[ \t]+(\d+)\b")
_SH_ERREXIT_RE = re.compile(r"set[ \t]+(?:-[a-zA-Z]*e[a-zA-Z]*|-o[ \t]+errexit)\b")
_SH_SHEBANG_E_RE = re.compile(r"#![^\n]*[ \t]-[a-zA-Z]*e[a-zA-Z]*\b")
_SH_FUNC_RE = re.compile(r"(?:function[ \t]+)?([\w-]+)[ \t]*(?:\(\))?[ \t]*\{")


def _shell_open(text: str) -> tuple[str, int] | None:
    errexit = 0
    trapped_words: set[str] = set()
    trap_closes = False
    closing_functions: set[str] = set()
    function = ""
    lines = text.splitlines()
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if number == 1 and _SH_SHEBANG_E_RE.match(line):
            errexit = 1
        if not line or line.startswith("#"):
            continue
        for match in _SH_EXIT_RE.finditer(line):
            if int(match.group(1)) not in (0, 2) and not _usage_path(lines, number):
                return f"it runs `exit {match.group(1)}`, and only exit 2 blocks", number
        if line.startswith("set +e"):
            errexit = 0
        elif _SH_ERREXIT_RE.match(line):
            errexit = errexit or number
        elif line.startswith("trap ") and re.search(r"\b(?:ERR|EXIT)\b", line):
            trapped_words.update(re.findall(r"[\w-]+", line))
            trap_closes = trap_closes or bool(_EXIT_TWO_RE.search(line))
        func_open = _SH_FUNC_RE.match(line)
        if func_open and "=" not in line and not line.startswith(("if ", "for ", "while ")):
            function = func_open.group(1)
        if function and _EXIT_TWO_RE.search(line):
            closing_functions.add(function)
        if line == "}":
            function = ""
    if errexit and not trap_closes and not trapped_words & closing_functions:
        return "`set -e` exits with the failing command's code, and only exit 2 blocks", errexit
    return None


_JS_TOKEN_RE = re.compile(
    r"\bcatch\b|uncaughtException|[{};]|process\.exit\(\s*(\d*)\s*\)|process\.exitCode\s*=\s*(\d+)"
    r"|[\"'](?:deny|block)[\"']|\b(?:function\s+|const\s+|let\s+|var\s+)([A-Za-z_$][\w$]*)|\b([A-Za-z_$][\w$]*)\("
)


@dataclass
class _NodeState:
    """One pass over a script's tokens: braces, the names they belong to, and the catch blocks."""

    depth: int = 0
    in_handler: int | None = None
    handler_pending: bool = False
    named: list[tuple[str, int]] = field(default_factory=list)
    name_pending: str = ""
    closed: bool = False
    blocking: set[str] = field(default_factory=set)
    called_in_handler: set[str] = field(default_factory=set)

    def in_catch(self) -> bool:
        return self.in_handler is not None or self.handler_pending

    def brace(self, opening: bool) -> None:
        if opening:
            if self.handler_pending and self.in_handler is None:
                self.in_handler = self.depth
                self.handler_pending = False
            if self.name_pending:
                self.named.append((self.name_pending, self.depth))
                self.name_pending = ""
            self.depth += 1
            return
        self.depth -= 1
        if self.in_handler == self.depth:
            self.in_handler = None
        if self.named and self.named[-1][1] == self.depth:
            self.named.pop()

    def exits_two(self) -> None:
        self.closed = self.closed or self.in_catch()
        self.blocking.update(name for name, _ in self.named)
        if self.name_pending:
            self.blocking.add(self.name_pending)


def _node_open(text: str) -> tuple[str, int] | None:
    """Read for tokens, not parsed: a brace or an exit in a comment or a string counts."""
    state = _NodeState()
    lines = text.splitlines()
    number, counted_to = 1, 0
    for match in _JS_TOKEN_RE.finditer(text):
        token = match.group(0)
        if token in ("catch", "uncaughtException"):
            state.handler_pending = True
        elif token in ("{", "}"):
            state.brace(token == "{")
        elif token == ";":
            state.name_pending = ""
        elif match.group(3):
            state.name_pending = match.group(3)
        elif match.group(4):
            if state.in_catch():
                state.called_in_handler.add(match.group(4))
        elif token[0] in "\"'":
            state.closed = state.closed or state.in_catch()
        else:
            code = int(match.group(1) or match.group(2) or 0)
            number += text.count("\n", counted_to, match.start())
            counted_to = match.start()
            if code not in (0, 2) and not _usage_path(lines, number):
                return f"it runs `{token}`, and only exit 2 blocks", number
            if code == 2:
                state.exits_two()
    if state.closed or state.called_in_handler & state.blocking:
        return None
    return "an uncaught exception or rejection exits 1, and no catch here exits 2", 1


# -- AAK-HOOK-FAILOPEN-001: the handlers ----------------------------------------------------------


def _hook_script(
    project_root: Path, rel_source: str, command: str, resolved: dict[tuple[str, str], Path | None],
) -> Path | None:
    """The script file inside the project that a hook's command line runs.

    `resolved` keeps what each word came to, since thousands of handlers may name one script
    and each resolve costs several system calls.
    """
    for word in _shell_words(command):
        var = _ROOT_VAR_RE.match(word)
        tail = word[var.end():] if var else word
        if Path(tail).suffix.lower() not in _SCRIPT_KINDS or tail.startswith(("/", "~", "$")):
            continue
        key = (rel_source, word)
        if key not in resolved:
            resolved[key] = _inside_project(project_root, rel_source, var.group(1) if var else "", tail)
        if resolved[key] is not None:
            return resolved[key]
    return None


def _inside_project(project_root: Path, rel_source: str, var: str, tail: str) -> Path | None:
    source = Path(rel_source)
    base = {
        "CLAUDE_PLUGIN_ROOT": project_root / source.parent.parent,
        "CLAUDE_SKILL_DIR": project_root / source.parent,
    }.get(var, project_root)
    try:
        candidate = (base / tail).resolve()
        return candidate if candidate.is_relative_to(project_root) and candidate.is_file() else None
    except (OSError, ValueError, RuntimeError):
        return None


def _script_verdict(path: Path, text: str) -> tuple[str, int] | None:
    kind = _SCRIPT_KINDS[path.suffix.lower()]
    if kind == "shell":
        return _shell_open(text)
    if kind == "node":
        return _node_open(text)
    try:
        tree = parse_python(text, path)
    except (SyntaxError, ValueError):
        return None
    with refusing_overflow(path):
        return walk_tree(_python_open, tree, text.splitlines())


def _read_script(script: Path, scanned: set[str], rel: str) -> tuple[bool, tuple[str, int] | None]:
    """Whether the script is a gate, and its verdict: why it fails open, or None if it does not."""
    try:
        text = read_text_capped(script, SOURCE_MAX_BYTES, errors="replace")
    except OSError:
        return False, None
    scanned.add(rel)
    return (True, _script_verdict(script, text)) if _is_gate(text) else (False, None)


def _swallowed_findings(rel_source: str, raw: str, commands: list[str]) -> list[Finding]:
    lines = find_line_numbers(raw, [c[:60] for c in commands])
    return [
        make_finding(
            RULE_HOOK, rel_source,
            f"PreToolUse hook `{c[:120]}` ends by swallowing the script's exit code, so any failure "
            f"reads as success and exit 2 never reaches Claude Code",
            lines.get(c[:60]),
        )
        for c in commands
    ]


def _hook_findings(project_root: Path, scanned: set[str]) -> list[Finding]:
    root = project_root.resolve()
    out: list[Finding] = []
    verdicts: dict[Path, tuple[bool, tuple[str, int] | None]] = {}
    resolved: dict[tuple[str, str], Path | None] = {}
    reported: set[str] = set()
    for rel_source, raw, hooks in _hook_sources(project_root, False, scanned):
        swallowed: dict[str, None] = {}
        for event, handler in iter_hook_handlers(hooks) if hooks else ():
            command = hook_command(handler) if event == "PreToolUse" else ""
            script = _hook_script(root, rel_source, command, resolved) if command else None
            if script is None:
                continue
            rel = script.relative_to(root).as_posix()
            if script not in verdicts:
                verdicts[script] = _read_script(script, scanned, rel)
            is_gate, verdict = verdicts[script]
            if not is_gate:
                continue
            if _SWALLOW_RE.search(command):
                swallowed[command] = None
            elif not _closed_by_handler(handler, command) and verdict and rel not in reported:
                reported.add(rel)
                out.append(make_finding(
                    RULE_HOOK, rel,
                    f"PreToolUse hook from {rel_source} fails open: {verdict[0]}; "
                    f"any other failure lets the tool call go ahead",
                    verdict[1],
                ))
        out.extend(_swallowed_findings(rel_source, raw, list(swallowed)))
    return out


def _closed_by_handler(handler: dict[str, Any], command: str) -> bool:
    """`... || exit 2` turns every failure of the script into a block, and so does onFailure."""
    if handler.get("onFailure") == "block":
        return True
    return "||" in command and bool(_EXIT_TWO_RE.search(command.rpartition("||")[2]))


_BYPASS_FLAGS = (
    "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions",
    "--permission-mode bypassPermissions", "--permission-mode=bypassPermissions",
)
_LAUNCH_FILES = ("README.md", "CONTRIBUTING.md", "CLAUDE.md", "AGENTS.md", "Makefile", "justfile", "package.json")
_WARNING_RE = re.compile(r"\b(?:never|don'?t|do not|avoid|without)\b", re.I)


def _documented_bypass(project_root: Path, scanned: set[str]) -> str | None:
    for name in _LAUNCH_FILES:
        path = project_root / name
        if not path.is_file():
            continue
        try:
            text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
        except OSError:
            continue
        scanned.add(name)
        for number, line in enumerate(text.splitlines(), 1):
            if "claude" in line and any(f in line for f in _BYPASS_FLAGS) and not _WARNING_RE.search(line):
                return f"a launch line in {name}:{number}"
    return None


def _ask_findings(project_root: Path, scanned: set[str]) -> list[Finding]:
    """`permissions.ask` as the control, with bypass mode still on the table."""
    ask_at: tuple[str, str] | None = None
    bypass = None
    for name in SETTINGS_FILES:
        path = project_root / name
        if not path.is_file():
            continue
        try:
            raw = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
            data = loads_json(raw, path)
        except (json.JSONDecodeError, OSError):
            continue
        permissions = data.get("permissions") if isinstance(data, dict) else None
        if not isinstance(permissions, dict):
            continue
        if permissions.get("disableBypassPermissionsMode") == "disable":
            return []
        if isinstance(permissions.get("ask"), list) and permissions["ask"] and ask_at is None:
            ask_at = (name, raw)
        if permissions.get("defaultMode") == "bypassPermissions":
            bypass = f"`defaultMode: bypassPermissions` in {name}"
    if ask_at is None:
        return []
    bypass = bypass or _documented_bypass(project_root, scanned)
    if bypass is None:
        return []
    return [make_finding(
        RULE_HOOK, ask_at[0],
        f"`permissions.ask` is the control here and bypass mode stays available ({bypass}), with no "
        f"`permissions.disableBypassPermissionsMode`: an ask rule is a prompt to a person, and reports "
        f"measure it not prompting under bypass",
        find_line_number(ask_at[1], '"ask"'),
    )]


# -- AAK-AGENT-SUBAGENT-TOOLS-001 -----------------------------------------------------------------

_AGENTS_DIR = ".claude/agents"
_SERVER_FILES = (".mcp.json", ".claude/settings.json", ".claude/settings.local.json")
_WRITE_KINDS = {
    **dict.fromkeys(("gmail", "mail", "email", "smtp", "sendgrid", "mailgun", "outlook", "postmark"), "mail"),
    **dict.fromkeys(("slack", "discord", "telegram", "whatsapp", "twilio", "teams"), "chat"),
    **dict.fromkeys(("calendar", "gcal"), "calendar"),
    **dict.fromkeys(("filesystem", "fs", "gdrive", "drive", "dropbox", "onedrive", "s3"), "files"),
    **dict.fromkeys(("github", "gitlab", "bitbucket", "jira", "linear", "notion", "confluence", "asana"), "tracker"),
    **dict.fromkeys(("postgres", "postgresql", "mysql", "sqlite", "mongo", "mongodb", "redis", "supabase"), "database"),
    **dict.fromkeys(("shell", "terminal", "ssh", "exec", "kubernetes", "kubectl", "terraform"), "shell"),
}
_WORD_RE = re.compile(r"[a-z0-9]+")
_READ_ONLY_RE = re.compile(r"read[-_]?only", re.I)
_UNQUOTED_WILDCARD_RE = re.compile(r"^tools:[ \t]*\*[ \t]*\r?$", re.M)
_SERVER_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")
_WITHHELD_RE = re.compile(r"mcp__([\w-]+?)(?:__\*)?")
# How many servers one finding names.
_NAMED_SERVERS = 8


def _write_kind(name: str, server: dict[str, Any]) -> str | None:
    """What a server writes to, going by its name and launch words. No config lists its tools."""
    args = server.get("args")
    args = [str(a) for a in args] if isinstance(args, list) else []
    env = server.get("env")
    names = [str(k) for k, v in env.items() if str(v).lower() not in ("0", "false")] if isinstance(env, dict) else []
    if any(_READ_ONLY_RE.search(word) for word in [*args, *names]):
        return None
    launch = [a for a in args if not a.startswith(("/", ".", "~", "-"))]
    text = " ".join([name, str(server.get("command") or ""), str(server.get("url") or ""), *launch]).lower()
    for word in _WORD_RE.findall(text):
        if word in _WRITE_KINDS:
            return _WRITE_KINDS[word]
    return None


def _write_servers(project_root: Path, scanned: set[str]) -> dict[str, str]:
    """`{normalized name: "name (kind)"}` for the project's MCP servers that write."""
    servers: dict[str, str] = {}
    for name in _SERVER_FILES:
        path = project_root / name
        if not path.is_file():
            continue
        try:
            data = loads_jsonc(read_text_capped(path, CONFIG_MAX_BYTES, errors="replace"), path)
        except (json.JSONDecodeError, OSError):
            continue
        scanned.add(name)
        for server_name, server in iter_mcp_servers(data):
            kind = _write_kind(str(server_name), server)
            if kind:
                servers.setdefault(_SERVER_NAME_RE.sub("_", str(server_name)), f"{server_name} ({kind})")
    return servers


def _tool_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [word.strip() for word in value.split(",")]
    return [str(word).strip() for word in value] if isinstance(value, list) else []


def _withheld(disallowed: list[str]) -> set[str] | None:
    """The server names `disallowedTools` withholds whole, or None when it withholds every one."""
    out: set[str] = set()
    for entry in disallowed:
        if entry == "mcp__*":
            return None
        match = _WITHHELD_RE.fullmatch(entry)
        if match:
            out.add(match.group(1))
    return out


def _agent_finding(
    path: Path, rel: str, servers: dict[str, str], order: list[str],
) -> Finding | None:
    text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
    frontmatter = _parse_frontmatter(_UNQUOTED_WILDCARD_RE.sub('tools: "*"', text, count=1), path)
    # Claude Code skips a file with no name or no description, so it is no subagent.
    if not frontmatter.get("name") or not frontmatter.get("description"):
        return None
    tools = _tool_list(frontmatter.get("tools"))
    if frontmatter.get("tools") is not None and not {"*", "mcp__*"} & set(tools):
        return None
    withheld = _withheld(_tool_list(frontmatter.get("disallowedTools")))
    withheld_here = sum(1 for key in withheld or () if key in servers)
    if withheld is None or withheld_here == len(servers):
        return None
    named: list[str] = []
    for key in order:
        if key not in withheld:
            named.append(servers[key])
            if len(named) == _NAMED_SERVERS:
                break
    how = "`tools` is a wildcard" if frontmatter.get("tools") is not None else "it has no `tools` line"
    more = ", and more" if len(servers) - withheld_here > len(named) else ""
    return make_finding(
        RULE_SUBAGENT, rel,
        f"subagent {str(frontmatter['name'])[:80]!r}: {how}, so it inherits the MCP servers this project "
        f"connects, including {', '.join(named)}{more}",
        find_line_number(text, "tools:") or 1,
    )


def _subagent_findings(project_root: Path, scanned: set[str]) -> list[Finding]:
    agents_dir = project_root / _AGENTS_DIR
    if not agents_dir.is_dir():
        return []
    servers = _write_servers(project_root, scanned)
    if not servers:
        return []
    order = sorted(servers)
    out: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(agents_dir):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".md"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(project_root).as_posix()
            try:
                finding = _agent_finding(path, rel, servers, order)
            except OSError:
                continue
            scanned.add(rel)
            if finding is not None:
                out.append(finding)
    return out


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report gates that pass when they have nothing to say.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    scanned: set[str] = set()
    findings = _python_findings(project_root, scanned)
    findings.extend(_hook_findings(project_root, scanned))
    findings.extend(_ask_findings(project_root, scanned))
    findings.extend(_subagent_findings(project_root, scanned))
    return findings, scanned


__all__ = ["RULE_OPTIONAL", "RULE_HOOK", "RULE_SUBAGENT", "scan"]
