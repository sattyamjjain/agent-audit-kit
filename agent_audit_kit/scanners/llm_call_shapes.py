"""Two small shapes around a model call, in Python.

* AAK-PROMPT-DELIMITER-001: untrusted text placed between prompt delimiters without escaping the
  closing one. `<user_input>{message}</user_input>` beats bare concatenation, and a message that
  contains `</user_input>` still closes the delimiter itself and writes what comes after it.
* AAK-LLM-NO-MAX-TOKENS-001: a web route or an agent tool that calls a chat completion with no output
  cap, so each request can spend up to the model's own limit. Read on every call it fired on 105 of
  194 public OpenAI callers, batch scripts included, which said nothing about who pays. A caller who
  can repeat the request is the part that matters, and read that way it fires on 4 of the 194.

What each rule reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Iterator

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, SOURCE_MAX_BYTES, make_finding, parse_python, read_text_capped, refusing_overflow, walk_tree

RULE_DELIMITER = "AAK-PROMPT-DELIMITER-001"
RULE_MAX_TOKENS = "AAK-LLM-NO-MAX-TOKENS-001"

_LLM_RE = re.compile(
    r"chat\.completions|ChatCompletion|\.messages\.create|responses\.create|ChatOpenAI|ChatAnthropic|generate_content"
    r"|\blitellm\b|\bollama\b|\bopenai\b|\banthropic\b|\blangchain\b"
)
_NOT_DEPLOYED = frozenset({
    "test", "tests", "testing", "fixture", "fixtures", "example", "examples", "sample", "samples", "demo", "demos",
})
_OPEN_TAG_RE = re.compile(r"<([A-Za-z][\w-]*)[^<>]*>\s*$")
_CLOSE_TAG_RE = re.compile(r"\s*</([A-Za-z][\w-]*)\s*>")
_OPEN_FENCE_RE = re.compile(r"(```|\"\"\"|'''|###|---|===|<<<)\s*$")
_CLOSE_FENCE_RE = re.compile(r"\s*(```|\"\"\"|'''|###|---|===|>>>)")
_HTML_TAGS = frozenset({
    "a", "b", "body", "br", "code", "div", "em", "h1", "h2", "h3", "h4", "h5", "h6", "head", "html", "i", "img", "li",
    "ol", "option", "p", "pre", "script", "span", "strong", "style", "table", "td", "th", "title", "tr", "u", "ul",
})
_CAP_KEYWORDS = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens", None})
_HANDLER_DECORATORS = frozenset({
    "get", "post", "put", "patch", "delete", "route", "api_route", "websocket", "tool", "function_tool", "call_tool",
})
_COMPLETION_CALLS = (
    "chat.completions.create", "ChatCompletion.create", "ChatCompletion.acreate", "litellm.completion", "litellm.acompletion",
)


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _own_nodes(nodes: list[ast.stmt]) -> Iterator[ast.AST]:
    stack: list[ast.AST] = list(reversed(nodes))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _root_name(node: ast.AST) -> str:
    """`message`, or the name under `request.message` and `data["message"]`."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _text(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _closes_delimiter(before: str, after: str) -> str | None:
    """The delimiter a value sits between, written the way it is, or None."""
    opening = _OPEN_TAG_RE.search(before)
    closing = _CLOSE_TAG_RE.match(after)
    if opening and closing and opening.group(1) == closing.group(1) and opening.group(1).lower() not in _HTML_TAGS:
        return f"</{closing.group(1)}>"
    fence = _OPEN_FENCE_RE.search(before)
    end = _CLOSE_FENCE_RE.match(after)
    if fence and end and (fence.group(1) == end.group(1) or (fence.group(1), end.group(1)) == ("<<<", ">>>")):
        return end.group(1)
    return None


def _delimiter_findings(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    params = {a.arg for a in [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]} - {"self", "cls"}
    if not params:
        return []
    strings: list[ast.JoinedStr] = []
    cleaned: set[str] = set()
    for node in _own_nodes(func.body):
        if isinstance(node, ast.JoinedStr):
            strings.append(node)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            # `message = message.replace("</x>", "")`, or anything else that rebinds it from a call.
            cleaned.update(t.id for t in node.targets if isinstance(t, ast.Name))
    out: list[Finding] = []
    for string in strings:
        values = string.values
        for index, value in enumerate(values[1:-1], 1):
            if not isinstance(value, ast.FormattedValue):
                continue
            name = _root_name(value.value)
            before, after = _text(values[index - 1]), _text(values[index + 1])
            if name in params and name not in cleaned and before is not None and after is not None:
                closing = _closes_delimiter(before, after)
                if closing:
                    out.append(make_finding(
                        RULE_DELIMITER, rel,
                        f"{func.name}() puts `{name}` between prompt delimiters without escaping `{closing}`: "
                        f"text that contains it closes the delimiter and writes what follows",
                        string.lineno,
                    ))
                    break
    return out


def _is_request_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A web route or an agent tool: a function a caller can run again and again."""
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _dotted(target).rpartition(".")[2] in _HANDLER_DECORATORS:
            return True
    return False


def _max_tokens_finding(func: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    for node in _own_nodes(func.body):
        if isinstance(node, ast.Call) and _dotted(node.func).endswith(_COMPLETION_CALLS) \
                and not any(k.arg in _CAP_KEYWORDS for k in node.keywords):
            return [make_finding(
                RULE_MAX_TOKENS, rel,
                f"{func.name}() answers requests and calls `{_dotted(node.func)}` with no `max_tokens` or "
                f"`max_completion_tokens`, so each request can spend up to the model's own limit",
                node.lineno,
            )]
    return []


def _analyse(tree: ast.Module, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for func in ast.walk(tree):
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_delimiter_findings(func, rel))
            if _is_request_handler(func):
                findings.extend(_max_tokens_finding(func, rel))
    return findings


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (
        any(p in _NOT_DEPLOYED for p in parts[:-1])
        or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"
    )


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report unescaped prompt delimiters and chat completions with no output cap.

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
            rel = path.relative_to(project_root).as_posix()
            if _is_test_path(rel):
                continue
            try:
                text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
            except OSError:
                continue
            if not _LLM_RE.search(text):
                continue
            try:
                tree = parse_python(text, path)
            except (SyntaxError, ValueError):
                continue
            with refusing_overflow(path):
                found = walk_tree(_analyse, tree, rel)
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["RULE_DELIMITER", "RULE_MAX_TOKENS", "scan"]
