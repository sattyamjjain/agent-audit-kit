"""Tree-sitter source-to-sink taint for AAK-MCP-STDIO-CMD-INJ-002 (#22).

The regex detector decides on *proximity*: a `new StdioClientTransport({...})`
counts as tainted when a network-controlled marker appears anywhere in the
preceding 1024 characters. That over-fires when an unrelated source happens to
sit nearby, and under-fires when a real source reaches the sink through a
variable or helper further away than the window.

This replaces the decision — for this one rule — with reachability over a real
parse. What the rule *reports* is unchanged: same rule_id, severity and
framework mappings. Only how it decides moved.

Deliberately optional. `tree_sitter` and `tree_sitter_typescript` are lazy
imported and never required: when the grammar is unavailable `available()`
returns False and the caller keeps its proximity behaviour, so the package stays
installable with no new hard dependency and offline with no download.

Scope is the slice #22 defines and nothing wider:

  sources  req.body / req.query / req.params (and `request.` forms),
           an awaited fetch(...) result, process.env.<VAR>, JSON.parse(...)
  sink     the `command` / `args` properties of a
           `new StdioClientTransport({...})` / `StdioServerTransport`
  flow     assignment, object destructuring, member access on a tainted base,
           template literals, and single-hop helper returns

Everything else in the epic — other TS sinks, Rust, Go — stays out.
"""

from __future__ import annotations

import functools
import re
from typing import Any, Optional

_SINK_CTORS = ("StdioClientTransport", "StdioServerTransport")
_SINK_PROPS = ("command", "args")

# Roots whose members are caller-controlled.
_TAINT_ROOTS = ("req", "request", "ctx", "context")
_TAINT_MEMBERS = ("body", "query", "params", "headers")

_MAX_DEPTH = 6


@functools.lru_cache(maxsize=1)
def _load() -> Optional[Any]:
    """Build the TS parser once, or return None when the grammar is absent."""
    try:
        import tree_sitter_typescript as ts_ts
        from tree_sitter import Language, Parser
    except Exception:
        return None
    try:
        return Parser(Language(ts_ts.language_typescript()))
    except Exception:
        return None


def available() -> bool:
    """True when the tree-sitter TS grammar can be used."""
    return _load() is not None


def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node: Any):
    yield node
    for child in node.children:
        yield from _walk(child)


def _is_taint_source(expr: str) -> bool:
    """Does this expression text name a caller-controlled source directly?"""
    for root in _TAINT_ROOTS:
        for member in _TAINT_MEMBERS:
            if re.search(rf"\b{root}\.{member}\b", expr):
                return True
    if re.search(r"\bprocess\.env\.[A-Za-z_][A-Za-z0-9_]*", expr):
        return True
    if re.search(r"\bJSON\.parse\s*\(", expr):
        return True
    if re.search(r"\bawait\s+fetch\s*\(", expr) or re.search(r"\bawait\s+axios\s*\.", expr):
        return True
    return False




class _Model:
    """Assignments and function returns collected once per file."""

    def __init__(self, root: Any, src: bytes) -> None:
        self.src = src
        # identifier -> list of RHS expression texts
        self.assign: dict[str, list[str]] = {}
        # function name -> list of returned expression texts
        self.returns: dict[str, list[str]] = {}
        self._collect(root)

    def _add_assign(self, name: str, value: str) -> None:
        self.assign.setdefault(name, []).append(value)

    def _collect(self, root: Any) -> None:
        for node in _walk(root):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is None or value_node is None:
                    continue
                value = _text(value_node, self.src)
                if name_node.type == "identifier":
                    self._add_assign(_text(name_node, self.src), value)
                else:
                    # Destructuring: `const { command, args } = body;` — each
                    # bound name inherits the taint of the right-hand side.
                    for sub in _walk(name_node):
                        if sub.type in ("shorthand_property_identifier_pattern", "identifier"):
                            self._add_assign(_text(sub, self.src), value)

            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None and left.type == "identifier":
                    self._add_assign(_text(left, self.src), _text(right, self.src))

            elif node.type in ("function_declaration", "method_definition", "function_expression"):
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    continue
                fname = _text(name_node, self.src)
                for sub in _walk(node):
                    if sub.type == "return_statement":
                        for child in sub.children:
                            if child.type not in ("return", ";"):
                                self.returns.setdefault(fname, []).append(_text(child, self.src))

    def tainted(self, expr: str, depth: int = 0) -> bool:
        """Does `expr` derive from a caller-controlled source?"""
        if depth > _MAX_DEPTH or not expr:
            return False
        if _is_taint_source(expr):
            return True

        # A single-hop helper call: `buildCommand(...)` -> its return expressions.
        for call in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", expr):
            for ret in self.returns.get(call.group(1), []):
                if self.tainted(ret, depth + 1):
                    return True

        # Any identifier in the expression whose assignment is tainted.
        for ident in set(re.findall(r"[A-Za-z_$][\w$]*", expr)):
            for rhs in self.assign.get(ident, []):
                if rhs.strip() == ident:
                    continue
                if self.tainted(rhs, depth + 1):
                    return True
        return False


def find_tainted_sink(source: str) -> Optional[int]:
    """Line of the first StdioTransport whose command/args derive from input.

    Returns None when nothing reaches a sink, or when the grammar is absent —
    the caller distinguishes those with `available()`.
    """
    parser = _load()
    if parser is None:
        return None
    src = source.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src)
    except Exception:
        return None

    model = _Model(tree.root_node, src)

    for node in _walk(tree.root_node):
        if node.type != "new_expression":
            continue
        ctor = node.child_by_field_name("constructor")
        if ctor is None or _text(ctor, src) not in _SINK_CTORS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        for prop in _walk(args):
            # `{ command: cmd }` — explicit key/value pair.
            if prop.type == "pair":
                key_node = prop.child_by_field_name("key")
                val_node = prop.child_by_field_name("value")
                if key_node is None or val_node is None:
                    continue
                if _text(key_node, src).strip("\"'") not in _SINK_PROPS:
                    continue
                if model.tainted(_text(val_node, src)):
                    return int(node.start_point[0]) + 1

            # `{ command, args }` — shorthand, where the identifier is both the
            # key and the value. This is the natural way to write the sink when
            # the value came from destructuring, which is one of the flows this
            # rule is meant to cover, so it must not be skipped.
            elif prop.type == "shorthand_property_identifier":
                name = _text(prop, src)
                if name in _SINK_PROPS and model.tainted(name):
                    return int(node.start_point[0]) + 1

        # `new StdioClientTransport(opts)` — the options object itself may be
        # a tainted variable rather than an inline literal.
        for child in args.children:
            if child.type == "identifier" and model.tainted(_text(child, src)):
                return int(node.start_point[0]) + 1

    return None
