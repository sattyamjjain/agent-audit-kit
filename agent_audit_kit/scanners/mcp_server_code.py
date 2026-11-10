"""Four shapes in MCP server code: what a tool hands back, says it does, or takes on trust.

* AAK-MCP-ENV-DUMP-001: a tool handler returns the whole process environment, so every
  credential in it is one tool call from the model. A read-only annotation makes that
  worse, since hosts auto-approve those. `@modelcontextprotocol/server-everything`'s
  `get-env` did this until 2.1.0 (commit f0c74aac, 27 Oct 2026), which masks credential-like
  values by default, so the config arm reads a stated release below that, a release on the
  package's date line, or a launch that sets `GET_ENV_INCLUDE_SECRETS`.
* AAK-MCP-ERROR-LEAK-001 (CWE-209): raw exception text in a client-facing error. A
  pydantic error reveals the backend down to its version, and an A2A executor sends the same
  text to a remote peer. A fixed message beside `logger.exception` loses nothing.
* AAK-MCP-ANNOTATION-MISMATCH-001: a tool annotated `readOnlyHint=True` or
  `destructiveHint=False` whose handler writes, deletes or rewrites storage. A tool with no
  annotations is not a mismatch: the MCP defaults (readOnlyHint false, destructiveHint true)
  already say it may write, and absent never reads as unknown.
* AAK-MCP-REQUESTSTATE-001: server code that takes an echoed `requestState` (the
  2026-07-28 input-required round trip) as proof of approval or identity. The client holds that
  value between requests, and the spec says that if it "influences authorisation, resource
  access, or business logic, servers MUST protect its integrity (e.g. HMAC or AEAD)".

Python is read through `parse_python`, TypeScript and JavaScript by pattern. What each rule
reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator

from agent_audit_kit.models import Finding

from ._helpers import (
    CONFIG_MAX_BYTES,
    SKIP_DIRS,
    SOURCE_MAX_BYTES,
    iter_mcp_servers,
    loads_jsonc,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    walk_tree,
)
from ._launchers import invocation_packages, npm_spec
from ._versions import parse_version

RULE_ENV = "AAK-MCP-ENV-DUMP-001"
RULE_ERROR = "AAK-MCP-ERROR-LEAK-001"
RULE_ANNOTATION = "AAK-MCP-ANNOTATION-MISMATCH-001"
RULE_STATE = "AAK-MCP-REQUESTSTATE-001"

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_CONFIG_NAMES = frozenset({".mcp.json", "mcp.json", "claude_desktop_config.json"})
# A config in one of these is not what anyone launches.
_NOT_DEPLOYED = frozenset({"test", "tests", "fixtures", "fixture", "example", "examples", "sample", "samples", "demo"})
_EVERYTHING = "@modelcontextprotocol/server-everything"
_EVERYTHING_MASKS = (2, 1, 0)
_EVERYTHING_DATE_LINE = (2025, 0, 0)
_INCLUDE_SECRETS = "GET_ENV_INCLUDE_SECRETS"

_TOOL_DECORATORS = frozenset({"tool", "call_tool"})


def _tail(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _tool_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.expr | None:
    """The decorator that registers this function as a tool: `@mcp.tool()`, `@app.call_tool()`."""
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr in _TOOL_DECORATORS:
            return decorator
    return None


def _own_nodes(nodes: list[ast.stmt]) -> Iterator[ast.AST]:
    """Every node under these statements, not entering a nested function or class."""
    stack: list[ast.AST] = list(reversed(nodes))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    found = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return sorted(found, key=lambda f: f.lineno)


# ---- the environment ------------------------------------------------------------------


def _whole_environ(node: ast.AST, names: set[str]) -> bool:
    """Does this expression hold the whole environment? `os.environ["X"]` and
    `os.environ.get("X")` read one variable, and do not."""
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Name) and current.id in names:
            return True
        if isinstance(current, ast.Subscript) and _dotted(current.value) == "os.environ":
            stack.append(current.slice)
            continue
        if isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute) \
                and current.func.attr == "get" and _dotted(current.func.value) == "os.environ":
            stack.extend(current.args)
            continue
        if isinstance(current, ast.Attribute) and _dotted(current) == "os.environ":
            return True
        stack.extend(ast.iter_child_nodes(current))
    return False


def _env_findings(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    decorator = _tool_decorator(func)
    if decorator is None:
        return []
    own = list(_own_nodes(func.body))
    held: set[str] = set()
    for node in own:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and _whole_environ(node.value, held):
            held.add(node.targets[0].id)
    for node in own:
        if isinstance(node, ast.Return) and node.value is not None and _whole_environ(node.value, held):
            note = " It is annotated read-only, so hosts that auto-approve those run it without asking." \
                if _hint(decorator, "readOnlyHint") is True else ""
            return [make_finding(
                RULE_ENV, rel,
                f"Tool handler `{func.name}` returns the whole process environment to the client, so every "
                f"credential in it is one tool call from the model.{note} Return the named variables it needs.",
                node.lineno,
            )]
    return []


_JS_TOOL_RE = re.compile(r"\.(?:tool|registerTool)\s*\(|setRequestHandler\s*\(\s*CallToolRequestSchema")
_JS_ENV_DUMP_RE = re.compile(
    r"JSON\.stringify\(\s*process\.env\s*[,)]"
    r"|(?:\breturn\b|\btext\s*:|\bcontent\s*:)[^;\n]{0,120}?(\{\s*\.\.\.process\.env\b|\bprocess\.env\b(?![\s]*[.\[?]))"
)
# `return spawn(cmd, { env: { ...process.env } })` hands it to a child, not to the client.
_JS_ENV_OPTION_RE = re.compile(r"\benv\s*:\s*$")


def _js_env_dump(text: str) -> int | None:
    """The offset of a `process.env` a tool hands back whole, or None."""
    for match in _JS_ENV_DUMP_RE.finditer(text):
        if match.start(1) >= 0 and _JS_ENV_OPTION_RE.search(text[max(0, match.start(1) - 16):match.start(1)]):
            continue
        return match.start()
    return None


def _config_env_findings(path: Path, rel: str) -> list[Finding]:
    if any(part.lower() in _NOT_DEPLOYED for part in Path(rel).parts[:-1]):
        return []
    try:
        data = loads_jsonc(read_text_capped(path, CONFIG_MAX_BYTES, errors="replace"), path)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for name, server in iter_mcp_servers(data):
        reason = _everything_reason(server)
        if reason:
            findings.append(make_finding(
                RULE_ENV, rel,
                f"Server '{name}' launches {_EVERYTHING}{reason}: its read-only `get-env` tool returns the "
                "credentials in the server's environment to the model. Use 2.1.0 or later, which masks them, "
                "without the opt-in, or leave this demo server out of a real config.",
            ))
    return findings


def _everything_reason(server: dict[str, Any]) -> str:
    """Why this launch dumps: a stated affected release, or the opt-in. An unpinned launch
    gets `latest`, which masks, so it is not reported."""
    command, args, env = server.get("command"), server.get("args"), server.get("env")
    argv = command.split() if isinstance(command, str) else []
    argv += [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    for launched in invocation_packages(argv):
        spec = npm_spec(launched.spec) if launched.ecosystem == "js" else None
        if spec is None or spec.kind != "registry" or spec.name != _EVERYTHING:
            continue
        opted = isinstance(env, dict) and str(env.get(_INCLUDE_SECRETS, "")).strip().lower() in ("1", "true", "yes", "on")
        if opted:
            return f" with {_INCLUDE_SECRETS} set"
        version = parse_version(spec.version) if spec.version else None
        if version is not None and (version < _EVERYTHING_MASKS or version >= _EVERYTHING_DATE_LINE):
            return f" at {spec.version}, which does not mask"
    return ""


# ---- raw exception text ---------------------------------------------------------------


# Errors a client or a remote peer reads. The names are common, so each counts only
# in a file that imports the protocol it belongs to: over 99,786 site-packages files,
# eight of fifteen first hits were `ToolError` in a library with no MCP in it.
_ERROR_SINKS = frozenset({"ToolError", "McpError", "ErrorData", "JSONRPCError", "ResourceError", "PromptError"})
_PEER_SINKS = frozenset({"new_agent_text_message", "TaskStatusUpdateEvent", "failed", "update_status"})
_MCP_IMPORT_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b", re.M)
_A2A_IMPORT_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:a2a\b|google\.adk\.a2a\b)", re.M)


def _exception_text(node: ast.AST, names: set[str]) -> str | None:
    """How an expression holds raw exception text: `str(e)`, `repr(e)`, `f"{e}"`,
    `"%s" % e`, `"{}".format(e)`, or `traceback.format_exc()`."""
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Call):
            func = current.func
            if _dotted(func) == "traceback.format_exc" or _tail(func) == "format_exc":
                return "traceback.format_exc()"
            if isinstance(func, ast.Name) and func.id in ("str", "repr") and current.args \
                    and isinstance(current.args[0], ast.Name) and current.args[0].id in names:
                return f"{func.id}({current.args[0].id})"
            if isinstance(func, ast.Attribute) and func.attr == "format" and any(
                    isinstance(a, ast.Name) and a.id in names for a in current.args):
                return "str.format"
        elif isinstance(current, ast.FormattedValue) and isinstance(current.value, ast.Name) \
                and current.value.id in names:
            return f"{{{current.value.id}}}"
        elif isinstance(current, ast.BinOp) and isinstance(current.op, ast.Mod) \
                and isinstance(current.right, ast.Name) and current.right.id in names:
            return "% formatting"
        stack.extend(ast.iter_child_nodes(current))
    return None


def _jsonrpc_error_dict(call_or_dict: ast.AST) -> ast.expr | None:
    """The `message` of a JSON-RPC error dict: `{"error": {"code": c, "message": m}}`."""
    if not isinstance(call_or_dict, ast.Dict):
        return None
    for key, value in zip(call_or_dict.keys, call_or_dict.values):
        if isinstance(key, ast.Constant) and key.value == "error" and isinstance(value, ast.Dict):
            for inner_key, inner in zip(value.keys, value.values):
                if isinstance(inner_key, ast.Constant) and inner_key.value == "message":
                    return inner
    return None


def _handler_leak(handler: ast.ExceptHandler, tool: bool, mcp: bool, a2a: bool) -> tuple[int, str, str] | None:
    """(line, how the text is held, where it goes) for the first leak in an except body."""
    names = {handler.name} if handler.name else set()
    for node in _own_nodes(handler.body):
        if isinstance(node, ast.Call):
            sink = _tail(node.func)
            if (mcp and sink in _ERROR_SINKS) or (a2a and sink in _PEER_SINKS):
                how = _exception_text(node, names)
                if how:
                    where = "a remote A2A peer" if sink in _PEER_SINKS else f"the client through `{sink}`"
                    return node.lineno, how, where
        message = _jsonrpc_error_dict(node) if mcp else None
        if message is not None:
            how = _exception_text(message, names)
            if how:
                return message.lineno, how, "the client in a JSON-RPC error"
        if tool and isinstance(node, ast.Return) and node.value is not None:
            how = _exception_text(node.value, set())
            if how:
                return node.lineno, how, "the client from a tool handler"
    return None


def _error_findings(tree: ast.Module, rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    mcp, a2a = bool(_MCP_IMPORT_RE.search(text)), bool(_A2A_IMPORT_RE.search(text))
    if not mcp and not a2a:
        return findings
    tool_handlers = {id(n) for f in _functions(tree) if _tool_decorator(f) for n in _own_nodes(f.body)}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        leak = _handler_leak(node, id(node) in tool_handlers, mcp, a2a)
        if leak is not None:
            line, how, where = leak
            findings.append(make_finding(
                RULE_ERROR, rel,
                f"Raw exception text ({how}) reaches {where}. It can show internals, versions and input values "
                "(CWE-209). Send a fixed message and log the detail with `logger.exception`.",
                line,
            ))
    return sorted(findings, key=lambda f: f.line_number or 0)


_JS_MCP_ERROR_LEAK_RE = re.compile(
    r"new\s+McpError\s*\([^;\n]{0,200}?(?:\b(?:err|error|e|ex|exc)\.(?:message|stack)\b|\bString\(\s*(?:err|error|e|ex|exc)\s*\)"
    r"|\$\{\s*(?:err|error|e|ex|exc)(?:\.(?:message|stack))?\s*\})"
)


# ---- annotations ----------------------------------------------------------------------


def _hint(decorator: ast.expr, name: str) -> bool | None:
    """The value of a hint in `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))`,
    `annotations={"readOnlyHint": True}` or `readOnlyHint=True`; None when absent."""
    if not isinstance(decorator, ast.Call):
        return None
    pending: list[ast.AST] = [decorator]
    while pending:
        call = pending.pop()
        if isinstance(call, ast.Call):
            for keyword in call.keywords:
                if keyword.arg == name and isinstance(keyword.value, ast.Constant):
                    return keyword.value.value if isinstance(keyword.value.value, bool) else None
                if keyword.arg == "annotations":
                    pending.append(keyword.value)
        elif isinstance(call, ast.Dict):
            for key, value in zip(call.keys, call.values):
                if isinstance(key, ast.Constant) and key.value == name and isinstance(value, ast.Constant):
                    return value.value if isinstance(value.value, bool) else None
    return None


_REMOVERS = frozenset({"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"})
_RENAMERS = frozenset({"os.rename", "os.replace", "shutil.move"})
_PATH_WRITES = frozenset({"write_text", "write_bytes"})
_SQL_REWRITE = re.compile(r"^\s*(DELETE|UPDATE|DROP|TRUNCATE|ALTER)\b", re.I)
_SQL_INSERT = re.compile(r"^\s*(INSERT|REPLACE|CREATE)\b", re.I)


def _literal_head(node: ast.AST | None) -> str:
    """The start of a string or f-string: the part a SQL verb is read from."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""
    return ""


def _open_mode(call: ast.Call) -> str:
    mode: ast.AST | None = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    return mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else ""


def _store_effect(call: ast.Call) -> tuple[str, bool] | None:
    """(what the call does, does it destroy or rewrite) when it changes storage."""
    name, tail = _dotted(call.func), _tail(call.func)
    if name in _REMOVERS or tail == "unlink":
        return f"`{name or tail}` deletes a file", True
    if name in _RENAMERS:
        return f"`{name}` moves a file", True
    if tail in _PATH_WRITES:
        return f"`{tail}` overwrites a file", True
    if name == "open":
        mode = _open_mode(call)
        if "w" in mode:
            return f'`open(..., "{mode}")` overwrites a file', True
        if "a" in mode or "x" in mode or "+" in mode:
            return f'`open(..., "{mode}")` writes a file', False
    if tail in ("execute", "executemany", "executescript") and call.args:
        head = _literal_head(call.args[0])
        verb = _SQL_REWRITE.match(head)
        if verb:
            return f"a SQL {verb.group(1).upper()} rewrites a table", True
        verb = _SQL_INSERT.match(head)
        if verb:
            return f"a SQL {verb.group(1).upper()} writes to a table", False
    return None


def _annotation_findings(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    decorator = _tool_decorator(func)
    if decorator is None:
        return []
    read_only = _hint(decorator, "readOnlyHint") is True
    not_destructive = _hint(decorator, "destructiveHint") is False
    if not read_only and not not_destructive:
        return []
    for node in _own_nodes(func.body):
        if not isinstance(node, ast.Call):
            continue
        effect = _store_effect(node)
        if effect is None:
            continue
        what, destroys = effect
        if read_only or destroys:
            hint = "readOnlyHint=True" if read_only else "destructiveHint=False"
            return [make_finding(
                RULE_ANNOTATION, rel,
                f"Tool `{func.name}` is annotated {hint}, but its handler changes storage: {what}. Hosts that "
                "auto-approve by these hints run it without asking. Correct the annotation, or remove the write.",
                node.lineno,
            )]
    return []


_JS_TOOL_SPLIT_RE = re.compile(r"\.(?:registerTool|tool)\s*\(")
_JS_READ_ONLY_RE = re.compile(r"\breadOnlyHint\s*:\s*true\b")
_JS_NOT_DESTRUCTIVE_RE = re.compile(r"\bdestructiveHint\s*:\s*false\b")
_JS_REWRITE_RE = re.compile(
    r"\b(?:fs(?:Promises|p)?\.)?(?:writeFile|writeFileSync|rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\("
    r"|[`\"']\s*(?:DELETE|UPDATE|DROP|TRUNCATE)\s", re.I)
_JS_STORE_FN_RE = re.compile(r"\bfs(?:Promises|p)?\.|\bunlink|\bwriteFile|[`\"']\s*(?:DELETE|UPDATE|DROP|TRUNCATE)\s", re.I)


def _js_annotation_findings(text: str, rel: str) -> list[Finding]:
    starts = [m.start() for m in _JS_TOOL_SPLIT_RE.finditer(text)] + [len(text)]
    findings: list[Finding] = []
    for start, stop in zip(starts, starts[1:]):
        hint = _JS_READ_ONLY_RE.search(text, start, stop) or _JS_NOT_DESTRUCTIVE_RE.search(text, start, stop)
        if hint is None:
            continue
        effect = _JS_REWRITE_RE.search(text, hint.end(), stop)
        if effect is not None and _JS_STORE_FN_RE.search(effect.group(0)):
            findings.append(make_finding(
                RULE_ANNOTATION, rel,
                f"A tool annotated `{hint.group(0)}` changes storage in the code that follows it "
                f"(`{effect.group(0).strip()[:40]}`). Hosts that auto-approve by these hints run it without "
                "asking. Correct the annotation, or remove the write.",
                text.count("\n", 0, effect.start()) + 1,
            ))
    return findings


# ---- requestState ---------------------------------------------------------------------


_STATE_RE = re.compile(r"\b(?:requestState|request_state)\b")
_DECODE_RE = re.compile(r"\b(?:b64decode|urlsafe_b64decode|atob|json\.loads|JSON\.parse|Buffer\.from)\b")
_TRUST_KEYS = r"approved|approval|authorized|authorised|allowed|principal|user|user_id|userId|identity|role|scope|scopes"
# The name is read whole and tested afterwards: a pattern with `state` inside `\\w*` on
# both sides backtracks quadratically over one long word holding it many times.
_TRUST_READ_RE = re.compile(
    rf"""\b(\w+)\s*(?:\[\s*["']({_TRUST_KEYS})["']\s*\]|\.get\(\s*["']({_TRUST_KEYS})["']|\.({_TRUST_KEYS})\b)"""
)
_VERIFY_RE = re.compile(
    r"\bcompare_digest\b|\bhmac\.|\btimingSafeEqual\b|\bcreateHmac\b|\bAESGCM\b|\bChaCha20\w*\b|\bcreateDecipheriv\b"
    r"|\bFernet\b|\bitsdangerous\b|\bjwt\.decode\b|\bjwtVerify\b|\bverify_signature\b|\bverifySignature\b"
)
_BINDINGS = (
    ("the principal", re.compile(r"\b(?:principal|sub|subject|user_id|userId|client_id|clientId)\b")),
    ("an expiry", re.compile(r"\b(?:exp|expires|expiry|expires_at|expiresAt|ttl|not_after)\b")),
    ("a digest of the request", re.compile(r"\b(?:digest|request_hash|requestHash|params_hash|paramsHash|sha256)\b")),
)


def _state_findings(text: str, rel: str) -> list[Finding]:
    if not _STATE_RE.search(text) or not _DECODE_RE.search(text):
        return []
    read = next((m for m in _TRUST_READ_RE.finditer(text) if "state" in m.group(1).lower()), None)
    if read is None:
        return []
    line = text.count("\n", 0, read.start()) + 1
    key = read.group(2) or read.group(3) or read.group(4)
    if not _VERIFY_RE.search(text):
        return [make_finding(
            RULE_STATE, rel,
            f"`{key}` is read from a decoded `requestState` with no HMAC or AEAD check in this file. The client "
            "holds that value between requests and can rewrite it. The 2026-07-28 spec says servers MUST protect its "
            "integrity when it influences authorisation.",
            line,
        )]
    missing = [label for label, pattern in _BINDINGS if not pattern.search(text)]
    if missing:
        return [make_finding(
            RULE_STATE, rel,
            f"`{key}` is read from a signed `requestState` that is not bound to {' or '.join(missing)}, so a valid "
            "state can be replayed for another caller or request. Bind it to all three, and enforce single use on the "
            "server.",
            line,
        )]
    return []


# ---- the walk -------------------------------------------------------------------------


def _python_findings(text: str, path: Path, rel: str) -> list[Finding]:
    try:
        tree = parse_python(text, path)
    except (SyntaxError, ValueError):
        return []
    findings: list[Finding] = []

    def _analyse() -> list[Finding]:
        found = _error_findings(tree, rel, text)
        for func in _functions(tree):
            found.extend(_env_findings(func, rel))
            found.extend(_annotation_findings(func, rel))
        return found

    with refusing_overflow(path):
        findings = walk_tree(_analyse)
    return findings


def _js_findings(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if _JS_TOOL_RE.search(text):
        dump = _js_env_dump(text)
        if dump is not None:
            findings.append(make_finding(
                RULE_ENV, rel,
                "A tool handler returns the whole of `process.env` to the client, so every credential in it is one "
                "tool call from the model. Return the named variables it needs.",
                text.count("\n", 0, dump) + 1,
            ))
        findings.extend(_js_annotation_findings(text, rel))
    leak = _JS_MCP_ERROR_LEAK_RE.search(text)
    if leak is not None:
        findings.append(make_finding(
            RULE_ERROR, rel,
            "Raw exception text reaches the client through `McpError`. It can show internals, versions and input "
            "values (CWE-209). Send a fixed message and log the detail.",
            text.count("\n", 0, leak.start()) + 1,
        ))
    return findings


# Cheap tests that keep most Python files from being parsed.
_PY_HINT_RE = re.compile(r"\.tool\b|call_tool|jsonrpc|ToolError|McpError|ErrorData|JSONRPCError|new_agent_text_message|TaskStatusUpdateEvent")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report env dumps, leaked exception text, false annotations and trusted requestState.

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
            path = Path(dirpath) / name
            lowered = name.lower()
            rel = path.relative_to(project_root).as_posix()
            if lowered in _CONFIG_NAMES or lowered.endswith(".mcp.json"):
                found = _config_env_findings(path, rel)
            elif name.endswith(".py") or name.endswith(_JS_EXTS):
                try:
                    text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
                except OSError:
                    continue
                found = _state_findings(text, rel)
                if name.endswith(".py"):
                    if _PY_HINT_RE.search(text):
                        found = _python_findings(text, path, rel) + found
                else:
                    found = _js_findings(text, rel) + found
            else:
                continue
            if found:
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["RULE_ENV", "RULE_ERROR", "RULE_ANNOTATION", "RULE_STATE", "scan"]
