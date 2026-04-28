"""Codemod: rewrite ToolNode(positional-list) -> ToolNode(tools=[...]).

Pairs with AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001. Run via
`aak suggest --apply-trivial --rule AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001`
(scaffolded; full apply queues for v0.4.0). Until then the rewrite is
text-level and best-effort: ToolNode([a, b]) -> ToolNode(tools=[a, b]).
"""

from __future__ import annotations

import re


_REWRITE_RE = re.compile(
    r"""
    (\bToolNode\s*\()
    (\s*\[)
    """,
    re.VERBOSE,
)


def fix(text: str) -> str:
    """Rewrite ``ToolNode([...]`` -> ``ToolNode(tools=[...]``.

    Idempotent on already-rewritten code.
    """
    return _REWRITE_RE.sub(r"\1tools=\2", text)
