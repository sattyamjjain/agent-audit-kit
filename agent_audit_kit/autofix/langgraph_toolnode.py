"""Codemod: rewrite ToolNode(positional-list) -> ToolNode(tools=[...]).

Pairs with AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001. Applied by `aak fix` (via
`fix._fix_langgraph_toolnode`) and by `aak suggest SARIF --apply-trivial`, which
runs the same fixes; neither takes a rule filter, so each applies every
auto-fixable rule's fix. A bare name (`ToolNode(tools_list)`) is not rewritten.

The rewrite is text-level: ToolNode([a, b]) -> ToolNode(tools=[a, b]). It is
idempotent, so re-running cannot double-apply.
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
